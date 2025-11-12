// smb_rebuilder.c
#define _GNU_SOURCE
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// -------------------- 기본 상수/구조 --------------------
#define ETH_HDR_LEN 14
#define SMB2_MAGIC_0 0xFE
#define SMB2_MAGIC_1 0x53 // 'S'
#define SMB2_MAGIC_2 0x4D // 'M'
#define SMB2_MAGIC_3 0x42 // 'B'

#define CMD_SMB2_READ   0x0008
#define CMD_SMB2_WRITE  0x0009

// SMB2 공통 헤더는 64바이트 고정
// 참고: 정확한 필드 정의는 MS-SMB2 문서 참고. 여기서는 필요한 것만 오프셋으로 접근.
typedef struct __attribute__((packed)) {
    uint8_t  ProtocolId[4];   // 0xFE 'S' 'M' 'B'
    uint16_t StructureSize;   // = 64
    uint16_t CreditCharge;
    uint32_t Status;          // 서버 응답 시 사용
    uint16_t Command;         // READ=0x0008, WRITE=0x0009 등
    uint16_t CreditRequest;   // or CreditResponse
    uint32_t Flags;
    uint32_t NextCommand;     // for compounded requests
    uint64_t MessageId;
    uint32_t ProcessId;       // (SMB2.0) or reserved
    uint32_t TreeId;
    uint64_t SessionId;
    uint8_t  Signature[16];
} SMB2Header;

// READ Response/Request, WRITE Request 구조는 길고 가변이라
// 여기서는 "필요한 필드의 오프셋"으로 안전하게 접근하는 방식 사용.
// 오프셋은 SMB2 사양 기준(버전에 따라 차이 가능). 학습용 MVP로 흔한 케이스를 가정.

// 간단 로거
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(1);
}

static void logi(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fprintf(stdout, "\n");
}

// -------------------- 파일 컨텍스트 관리 --------------------
// FileId(16B) -> 파일 핸들 매핑. 간단히 배열/리스트로.
typedef struct FileCtx {
    uint8_t  file_id[16]; // SMB2 FileId
    char     path[512];   // 출력 경로
    int      fd;          // 열린 파일 디스크립터
    struct FileCtx *next;
} FileCtx;

typedef struct {
    FileCtx *head;
    char outdir[512];
} FileTable;

static FileTable g_ft = { .head = NULL, .outdir = "/tmp/smb_rebuild" };

static void hexify(const uint8_t *in, size_t n, char *out, size_t outsz) {
    static const char *h = "0123456789abcdef";
    size_t j = 0;
    for (size_t i = 0; i < n && j + 2 < outsz; ++i) {
        out[j++] = h[in[i] >> 4];
        out[j++] = h[in[i] & 0xF];
    }
    if (j < outsz) out[j] = 0;
}

static FileCtx* find_or_open_filectx(const uint8_t file_id[16]) {
    for (FileCtx *p = g_ft.head; p; p = p->next) {
        if (memcmp(p->file_id, file_id, 16) == 0) return p;
    }
    // 없으면 새로 만들기
    FileCtx *fc = (FileCtx*)calloc(1, sizeof(FileCtx));
    memcpy(fc->file_id, file_id, 16);
    // 파일명은 일단 unknown_<fileid>.part 형태
    char fidhex[33]; hexify(file_id, 16, fidhex, sizeof(fidhex));
    snprintf(fc->path, sizeof(fc->path), "%s/unknown_%s.part", g_ft.outdir, fidhex);

    fc->fd = open(fc->path, O_CREAT | O_WRONLY, 0644);
    if (fc->fd < 0) {
        free(fc);
        die("open(%s) failed: %s", fc->path, strerror(errno));
    }
    // 링크드리스트에 추가
    fc->next = g_ft.head;
    g_ft.head = fc;

    logi("[OPEN] %s", fc->path);
    return fc;
}

static void pwrite_all(int fd, const void *buf, size_t len, off_t offset) {
    const uint8_t *p = (const uint8_t*)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t w = pwrite(fd, p + done, len - done, offset + done);
        if (w < 0) die("pwrite failed: %s", strerror(errno));
        done += (size_t)w;
    }
}

// -------------------- 네트워크 계층 파서 --------------------
static const uint8_t* parse_ipv4(const uint8_t *l3, const uint8_t *end, uint8_t *out_proto, uint16_t *out_totlen) {
    if (l3 + 20 > end) return NULL;
    uint8_t ver_ihl = l3[0];
    uint8_t ihl = (ver_ihl & 0x0F) * 4; // IHL in 32-bit words
    if (ihl < 20) return NULL;
    if (l3 + ihl > end) return NULL;
    *out_proto = l3[9];
    *out_totlen = ntohs(*(uint16_t*)(l3 + 2));
    // 데이터 시작은 l3 + ihl
    return l3 + ihl;
}

static const uint8_t* parse_tcp(const uint8_t *l4, const uint8_t *end, uint16_t *out_sport, uint16_t *out_dport, uint8_t *out_hdrlen) {
    if (l4 + 20 > end) return NULL;
    *out_sport = ntohs(*(uint16_t*)(l4 + 0));
    *out_dport = ntohs(*(uint16_t*)(l4 + 2));
    uint8_t data_off = (l4[12] >> 4) & 0x0F; // in 32-bit words
    *out_hdrlen = data_off * 4;
    if (*out_hdrlen < 20) return NULL;
    if (l4 + *out_hdrlen > end) return NULL;
    return l4 + *out_hdrlen;
}

// -------------------- SMB2 헬퍼 --------------------
static bool is_smb2(const uint8_t *p, const uint8_t *end) {
    if (p + sizeof(SMB2Header) > end) return false;
    return (p[0] == SMB2_MAGIC_0 && p[1] == SMB2_MAGIC_1 && p[2] == SMB2_MAGIC_2 && p[3] == SMB2_MAGIC_3);
}

static uint16_t read_le16(const void *vp) {
    const uint8_t *p = (const uint8_t*)vp;
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t read_le32(const void *vp) {
    const uint8_t *p = (const uint8_t*)vp;
    return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

static uint64_t read_le64(const void *vp) {
    const uint8_t *p = (const uint8_t*)vp;
    return (uint64_t)p[0]
        | ((uint64_t)p[1] << 8)
        | ((uint64_t)p[2] << 16)
        | ((uint64_t)p[3] << 24)
        | ((uint64_t)p[4] << 32)
        | ((uint64_t)p[5] << 40)
        | ((uint64_t)p[6] << 48)
        | ((uint64_t)p[7] << 56);
}

// SMB2 공통 헤더 뒤에 오는 구조에서 FileId/Offset/DataLength 등을 뽑는다.
// READ Response (서버→클라) 일반적 구조(요약):
//  - 헤더(64) + READ Response 헤더(16B 고정 + 가변?) 중에 DataOffset(2), DataLength(4) 등 존재
//  - FileId는 READ 요청에 있고 응답에는 없음 → 실전은 "요청-응답 매칭" 필요
//   *MVP 단순화*: WRITE 요청(클라→서버)만으로도 파일 재조합 가능(업로드 트래픽이라 데이터가 요청에 포함).
//   READ 응답까지 하려면 TCP/SMB2 상의 MessageId로 요청-응답 매칭 로직을 추가해야 함.

typedef struct {
    // WRITE Request 필드(일반적 오프셋; 버전에 따라 다를 수 있음)
    // StructureSize:2 (고정=49), DataOffset:2, Length:4, Offset:8, FileId:16, Data이 뒤에 옴
    uint16_t StructSize;
    uint16_t DataOffset;
    uint32_t DataLength;
    uint64_t Offset;
    uint8_t  FileId[16];
    // 그 외 생략
} SMB2WriteReqMini;

// 주의: 실제 SMB2 WRITE Request의 필드 배치는 64바이트 공통 헤더 이후에 위치.
// 여기서는 "공통헤더(64) 뒤의 고정부분"이 최소한 위 멤버를 포함한다고 가정하고 오프셋 접근.
static bool parse_smb2_write_request(const uint8_t *smb, const uint8_t *end,
                                     SMB2WriteReqMini *out, const uint8_t **out_data) {
    // 공통헤더 뒤 최소 0x31(49) 구조 크기 이상 존재해야
    if (smb + sizeof(SMB2Header) + 48 > end) return false; // 대략적인 안전성 체크
    const SMB2Header *h = (const SMB2Header*)smb;

    // 공통헤더 다음을 가리킴
    const uint8_t *p = smb + sizeof(SMB2Header);
    if (p + 49 > end) return false; // StructureSize(49)까지 최소 보장 가정

    out->StructSize = read_le16(p + 0);
    out->DataOffset = read_le16(p + 2);
    out->DataLength = read_le32(p + 4);
    out->Offset     = read_le64(p + 8);

    // FileId는 공통헤더 뒤 24바이트 이후 16바이트 (일반적인 케이스)
    memcpy(out->FileId, p + 24, 16);

    // DataOffset은 패킷 전체 시작을 기준 아님. SMB 메시지 기준(=공통헤더 시작)을 기준으로 하는 경우가 많음.
    // 여기서는 "SMB2 헤더 시작(smb) 기준"으로 DataOffset을 적용.
    const uint8_t *data_start = smb + out->DataOffset;
    if (data_start + out->DataLength > end) return false;

    *out_data = data_start;
    return true;
}

// -------------------- 패킷 처리 --------------------
static void handle_tcp_payload(const uint8_t *pay, size_t paylen) {
    const uint8_t *p = pay, *end = pay + paylen;

    // 하나의 TCP 페이로드에 복수 SMB 메시지가 연속(compound)될 수 있음.
    while (p + sizeof(SMB2Header) <= end) {
        if (!is_smb2(p, end)) {
            // SMB2 매직 아니면 break (혹은 p++로 스캔하지만, 여기선 종료)
            break;
        }
        const SMB2Header *h = (const SMB2Header*)p;
        uint16_t cmd = read_le16(&h->Command);

        // 다음 명령(Compounded) 계산: h->NextCommand가 0이 아니면 그 길이만큼 다음 메시지 존재
        uint32_t next = read_le32(&h->NextCommand);
        const uint8_t *msg_end = next ? (p + next) : end;

        if (cmd == CMD_SMB2_WRITE) {
            SMB2WriteReqMini wr = {0};
            const uint8_t *data_ptr = NULL;
            if (parse_smb2_write_request(p, end, &wr, &data_ptr)) {
                FileCtx *fc = find_or_open_filectx(wr.FileId);
                pwrite_all(fc->fd, data_ptr, wr.DataLength, (off_t)wr.Offset);
                // 진행 로그(너무 시끄러우면 주석)
                // logi("[WRITE] off=%lu len=%u -> %s", (unsigned long)wr.Offset, wr.DataLength, fc->path);
            }
        }
        else {
            // TODO: READ 응답 처리하고 싶으면 요청-응답 매칭(MessageId)로 FileId/Offset/Length를 찾아서 data 영역 쓰기
        }

        if (next == 0) break;
        if (p + next > end) break; // 방어
        p += next;
    }
}

static void on_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    const uint8_t *p = bytes;
    const uint8_t *end = bytes + h->caplen;

    if (h->caplen < ETH_HDR_LEN) return;

    // EtherType
    uint16_t eth_type = ntohs(*(uint16_t*)(p + 12));
    if (eth_type != 0x0800) { // IPv4만
        return;
    }
    const uint8_t *l3 = p + ETH_HDR_LEN;
    uint8_t proto = 0; uint16_t ip_totlen = 0;
    const uint8_t *l4 = parse_ipv4(l3, end, &proto, &ip_totlen);
    if (!l4) return;
    if (proto != 6) return; // TCP만

    uint16_t sport=0, dport=0; uint8_t tcphl=0;
    const uint8_t *app = parse_tcp(l4, end, &sport, &dport, &tcphl);
    if (!app) return;

    // BPF로 이미 걸렀겠지만, 안전하게 445포트만
    if (sport != 445 && dport != 445) return;

    size_t app_len = (size_t)(end - app);
    if (app_len == 0) return;

    // MVP: TCP 재조립 없음. 페이로드 그대로 파싱 시도
    handle_tcp_payload(app, app_len);
}

// -------------------- 메인 --------------------
static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage:\n"
        "  %s -r <pcapfile> [-o outdir]\n"
        "  %s -i <iface>    [-o outdir]\n"
        , argv0, argv0);
}

int main(int argc, char **argv) {
    const char *pcapfile = NULL;
    const char *iface = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    // 기본 출력 디렉토리
    snprintf(g_ft.outdir, sizeof(g_ft.outdir), "/tmp/smb_rebuild");

    int opt;
    while ((opt = getopt(argc, argv, "r:i:o:")) != -1) {
        switch (opt) {
            case 'r': pcapfile = optarg; break;
            case 'i': iface = optarg; break;
            case 'o': snprintf(g_ft.outdir, sizeof(g_ft.outdir), "%s", optarg); break;
            default: usage(argv[0]); return 1;
        }
    }
    if (!pcapfile && !iface) { usage(argv[0]); return 1; }

    // 출력 디렉토리 준비
    mkdir(g_ft.outdir, 0755);

    pcap_t *pcap = NULL;
    if (pcapfile) {
        pcap = pcap_open_offline(pcapfile, errbuf);
        if (!pcap) die("pcap_open_offline failed: %s", errbuf);
    } else {
        pcap = pcap_open_live(iface, 65535, 1, 10, errbuf);
        if (!pcap) die("pcap_open_live failed: %s", errbuf);
    }

    // BPF 필터: tcp port 445
    struct bpf_program fp;
    if (pcap_compile(pcap, &fp, "tcp port 445", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        die("pcap_compile error: %s", pcap_geterr(pcap));
    }
    if (pcap_setfilter(pcap, &fp) == -1) {
        die("pcap_setfilter error: %s", pcap_geterr(pcap));
    }
    pcap_freecode(&fp);

    logi("[START] SMB2 file rebuild to %s", g_ft.outdir);
    int rc = pcap_loop(pcap, -1, on_packet, NULL);
    if (rc == -2) {
        // pcap_breakloop 로 종료된 경우
    } else if (rc == -1) {
        die("pcap_loop error: %s", pcap_geterr(pcap));
    }

    pcap_close(pcap);
    logi("[DONE] Check output dir: %s", g_ft.outdir);
    return 0;
}
