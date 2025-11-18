/*
 * smb_reassembler.c
 *
 * This program reconstructs files transferred over SMB protocols by passively
 * sniffing TCP traffic.  Unlike the original example which only supported
 * SMB2 over port 445, this version attempts to detect SMB traffic on both
 * the traditional ports (445 for SMB2/3 and 139 for SMB1) and perform
 * rudimentary parsing of SMB1, SMB2 and SMB3 messages.  SMB2 and SMB3 are
 * treated identically here because SMB3 uses the same base header format
 * but may include transform headers for encryption or compression.  SMB1
 * support is limited to extracting data from WRITE requests; read responses
 * and other commands are not handled.  For SMB2/3 the code reassembles
 * TCP streams, parses NBSS headers and SMB2 packet headers, tracks
 * pending READ requests and reconstructs file contents.
 *
 * Limitations:
 *   - Only IPv4/TCP traffic is supported; IPv6 and fragmentation are not
 *     handled.
 *   - SMB1 support is partial: only WRITE requests are processed.  READ
 *     responses and proper offset handling are not implemented.  SMB1
 *     files are identified by their FID plus connection endpoints and
 *     written to unique filenames derived from those values.
 *   - SMB2/3 reassembly drops out‑of‑order TCP segments as in the original
 *     example.  SMB3 encryption and compression are not supported; any
 *     encrypted/transform messages are ignored.
 *   - For simplicity, server determination is based on the presence of
 *     ports 445 or 139.  Traffic on other ports is ignored.
 *
 * Usage:
 *     ./smb_reassembler <pcap_file> <output_dir>
 *
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Connection key identifying one SMB TCP connection.
 * For each direction we track a separate TCP sequence number and SMB parsing
 * state.  The endpoint using port 445 or 139 is treated as the server and
 * the other endpoint as the client.  */
typedef struct conn_key {
    uint32_t cli_ip;
    uint16_t cli_port;
    uint32_t srv_ip;
    uint16_t srv_port;
} conn_key_t;

/* State for one direction of a TCP stream (client→server or server→client). */
typedef struct tcp_stream {
    uint32_t next_seq;
    int has_next_seq;
} tcp_stream_t;

/* Pending READ request awaiting a response (SMB2/3). */
typedef struct pending_read {
    uint64_t msg_id;
    uint8_t file_id[16];
    uint64_t offset;
    uint32_t length;
    struct pending_read *next;
} pending_read_t;

/* SMB stream state for one direction. */
typedef struct smb_stream {
    uint8_t *buf;
    size_t buf_len;
    size_t buf_cap;
    pending_read_t *pending; /* linked list of pending READ requests */
} smb_stream_t;

/* Per‑connection context storing both TCP and SMB state. */
typedef struct connection {
    conn_key_t key;
    tcp_stream_t tcp[2]; /* 0 = client→server, 1 = server→client */
    smb_stream_t smb[2];
    struct connection *next;
} connection_t;

/* Linked list of all connections. */
static connection_t *connections = NULL;

/* File context storing open file handles keyed by FileId. */
typedef struct file_ctx {
    uint8_t file_id[16];
    FILE *fp;
    struct file_ctx *next;
} file_ctx_t;

static file_ctx_t *open_files = NULL;
static char *output_dir = NULL;

/* SMB1 command codes of interest. */
enum smb1_commands {
    SMB1_COM_WRITE       = 0x0B,
    SMB1_COM_WRITE_ANDX  = 0x2F
};

/* SMB2 opcodes of interest. */
enum smb2_commands {
    SMB2_READ  = 0x0008,
    SMB2_WRITE = 0x0009
};

/* SMB2 flags bit. */
static const uint32_t SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001;

/* Utility: Compare two connection keys. */
static int conn_key_equal(const conn_key_t *a, const conn_key_t *b) {
    return a->cli_ip == b->cli_ip && a->cli_port == b->cli_port &&
           a->srv_ip == b->srv_ip && a->srv_port == b->srv_port;
}

/* Find or create a connection context for the given key. */
static connection_t *get_connection(const conn_key_t *key) {
    connection_t *c;
    for (c = connections; c; c = c->next) {
        if (conn_key_equal(&c->key, key))
            return c;
    }
    /* not found: allocate new */
    c = (connection_t *)calloc(1, sizeof(connection_t));
    if (!c) {
        fprintf(stderr, "memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    c->key = *key;
    /* init SMB stream buffers */
    for (int i = 0; i < 2; i++) {
        c->smb[i].buf = NULL;
        c->smb[i].buf_len = 0;
        c->smb[i].buf_cap = 0;
        c->smb[i].pending = NULL;
        c->tcp[i].has_next_seq = 0;
    }
    /* insert at head */
    c->next = connections;
    connections = c;
    return c;
}

/* Utility: ensure buffer can hold at least needed bytes. */
static void ensure_capacity(smb_stream_t *s, size_t needed) {
    if (s->buf_cap >= needed)
        return;
    size_t new_cap = s->buf_cap ? s->buf_cap * 2 : 1024;
    while (new_cap < needed)
        new_cap *= 2;
    uint8_t *new_buf = (uint8_t *)realloc(s->buf, new_cap);
    if (!new_buf) {
        fprintf(stderr, "realloc failed\n");
        exit(EXIT_FAILURE);
    }
    s->buf = new_buf;
    s->buf_cap = new_cap;
}

/* Write file chunk to output file identified by FileId.  The fileId must be
 * exactly 16 bytes.  If the file does not yet exist in the list of open
 * files, a new file is created in the output directory using the hex
 * representation of the FileId as its name. */
static void write_file_chunk(const uint8_t *file_id, uint64_t offset, const uint8_t *data, size_t len) {
    file_ctx_t *ctx;
    for (ctx = open_files; ctx; ctx = ctx->next) {
        if (memcmp(ctx->file_id, file_id, 16) == 0)
            break;
    }
    if (!ctx) {
        ctx = (file_ctx_t *)calloc(1, sizeof(file_ctx_t));
        if (!ctx) {
            fprintf(stderr, "memory allocation failed\n");
            exit(EXIT_FAILURE);
        }
        memcpy(ctx->file_id, file_id, 16);
        /* construct filename as hex string */
        char hexname[33];
        for (int i = 0; i < 16; i++)
            sprintf(&hexname[i * 2], "%02x", file_id[i]);
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", output_dir, hexname);
        ctx->fp = fopen(path, "wb");
        if (!ctx->fp) {
            fprintf(stderr, "failed to open output file %s\n", path);
            exit(EXIT_FAILURE);
        }
        ctx->next = open_files;
        open_files = ctx;
    }
    /* write chunk at offset */
    fseeko(ctx->fp, (off_t)offset, SEEK_SET);
    fwrite(data, 1, len, ctx->fp);
}

/* SMB2 message handling functions (copied from the original code). */

/* Handle a SMB2 WRITE request (client→server).  Extracts the payload and
 * writes it to the output file. */
static void parse_write_request(const uint8_t *body, size_t len) {
    if (len < 32)
        return;
    /* In SMB2 WRITE request: body[0:2] struct_size, body[2:4] data_offset,
     * body[4:8] data_length, body[8:16] file_offset, body[24:40] FileId,
     * body[data_offset: data_offset+data_length] data. */
    uint16_t data_offset = body[2] | (body[3] << 8);
    uint32_t data_length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24);
    uint64_t file_offset = 0;
    for (int i = 0; i < 8; i++)
        file_offset |= ((uint64_t)body[8 + i]) << (8 * i);
    const uint8_t *file_id = body + 24;
    size_t data_start = data_offset;
    size_t data_end = data_start + data_length;
    if (len < data_end)
        return;
    const uint8_t *data = body + data_start;
    write_file_chunk(file_id, file_offset, data, data_length);
}

/* Record a pending SMB2 READ request (client→server). */
static void record_pending_read(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    if (len < 48)
        return;
    uint32_t length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24);
    uint64_t offset = 0;
    for (int i = 0; i < 8; i++)
        offset |= ((uint64_t)body[8 + i]) << (8 * i);
    const uint8_t *file_id = body + 24;
    /* allocate new pending entry */
    pending_read_t *pr = (pending_read_t *)calloc(1, sizeof(pending_read_t));
    if (!pr) {
        fprintf(stderr, "memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    pr->msg_id = msg_id;
    memcpy(pr->file_id, file_id, 16);
    pr->offset = offset;
    pr->length = length;
    /* insert at head */
    pr->next = conn->smb[0].pending;
    conn->smb[0].pending = pr;
}

/* Handle a SMB2 READ response (server→client).  Matches a pending READ
 * request and writes the received data to the output file. */
static void handle_read_response(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    if (len < 16)
        return;
    uint8_t data_offset = body[2];
    uint32_t data_length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24);
    size_t data_start = data_offset;
    size_t data_end = data_start + data_length;
    if (len < data_end)
        return;
    const uint8_t *data = body + data_start;
    /* find matching pending read */
    pending_read_t **prev_ptr = &conn->smb[0].pending;
    pending_read_t *pr = conn->smb[0].pending;
    while (pr) {
        if (pr->msg_id == msg_id)
            break;
        prev_ptr = &pr->next;
        pr = pr->next;
    }
    if (!pr)
        return;
    /* remove from list */
    *prev_ptr = pr->next;
    /* write data */
    write_file_chunk(pr->file_id, pr->offset, data, data_length);
    free(pr);
}

/* Parse and handle a single SMB2 message. */
static void parse_smb2_message(connection_t *conn, int dir, const uint8_t *msg, size_t len) {
    if (len < 64)
        return;
    /* Check protocol ID FE 'S' 'M' 'B' */
    if (!(msg[0] == 0xFE && msg[1] == 'S' && msg[2] == 'M' && msg[3] == 'B'))
        return;
    uint16_t struct_size = msg[4] | (msg[5] << 8);
    if (struct_size != 64)
        return;
    uint16_t command = msg[12] | (msg[13] << 8);
    uint32_t flags = msg[16] | (msg[17] << 8) | (msg[18] << 16) | (msg[19] << 24);
    uint64_t msg_id = 0;
    for (int i = 0; i < 8; i++)
        msg_id |= ((uint64_t)msg[24 + i]) << (8 * i);
    int is_response = (flags & SMB2_FLAGS_SERVER_TO_REDIR) != 0;
    const uint8_t *body = msg + 64;
    size_t body_len = len - 64;
    if (!is_response) {
        /* Request */
        if (command == SMB2_READ && dir == 0) {
            record_pending_read(conn, msg_id, body, body_len);
        } else if (command == SMB2_WRITE && dir == 0) {
            parse_write_request(body, body_len);
        }
    } else {
        /* Response */
        if (command == SMB2_READ && dir == 1) {
            handle_read_response(conn, msg_id, body, body_len);
        }
        /* Note: WRITE responses carry no file data */
    }
}

/* Create a 16‑byte file ID for SMB1 by combining FID and connection
 * endpoints.  The first two bytes contain the FID (little endian).  The
 * next six bytes contain the client IP and port (IP in network order,
 * port in network order), then six bytes contain the server IP and port.
 * The remaining two bytes are zero. */
static void create_file_id_smb1(const connection_t *conn, uint16_t fid, uint8_t file_id[16]) {
    memset(file_id, 0, 16);
    file_id[0] = (uint8_t)(fid & 0xFF);
    file_id[1] = (uint8_t)((fid >> 8) & 0xFF);
    /* copy client IP (4 bytes) and port (2 bytes) */
    memcpy(&file_id[2], &conn->key.cli_ip, 4);
    uint16_t cli_port = htons(conn->key.cli_port);
    memcpy(&file_id[6], &cli_port, 2);
    /* copy server IP (4 bytes) and port (2 bytes) */
    memcpy(&file_id[8], &conn->key.srv_ip, 4);
    uint16_t srv_port = htons(conn->key.srv_port);
    memcpy(&file_id[12], &srv_port, 2);
}

/* Parse and handle a single SMB1 message.  Only SMB_COM_WRITE and
 * SMB_COM_WRITE_ANDX (WRITE ANDX) requests are processed.  Data is
 * appended to a file identified by FID plus connection endpoints.
 */
static void parse_smb1_message(connection_t *conn, int dir, const uint8_t *msg, size_t len) {
    /* SMB1 header is 32 bytes after NBSS header.  We assume NBSS header has
     * already been removed. */
    if (len < 32)
        return;
    /* Protocol ID 0xFF 'S' 'M' 'B' */
    if (!(msg[0] == 0xFF && msg[1] == 'S' && msg[2] == 'M' && msg[3] == 'B'))
        return;
    uint8_t command = msg[4];
    /* Word count at offset 32 */
    if (len < 33)
        return;
    uint8_t word_count = msg[32];
    const uint8_t *params = msg + 33;
    size_t params_len = (size_t)word_count * 2;
    if (len < 33 + params_len + 2)
        return;
    uint16_t byte_count = params[params_len] | (params[params_len + 1] << 8);
    const uint8_t *data_base = params + params_len + 2;
    if (data_base + byte_count > msg + len)
        return;
    if (dir != 0) {
        /* SMB1 writes are always client→server.  Ignore anything else. */
        return;
    }
    /* Handle SMB_COM_WRITE_ANDX (0x2F) */
    if (command == SMB1_COM_WRITE_ANDX) {
        /* At least 12 parameter words are expected. */
        if (word_count < 12)
            return;
        /* Parameter words are 2 bytes each.  According to CIFS spec, the
         * structure is: AndXCommand (1), AndXReserved (1), AndXOffset (2),
         * FID (2), Offset (4), Timeout (4), WriteMode (2), Remaining (2),
         * DataLength (2), DataOffset (2), OffsetHigh (4).  We are only
         * interested in FID, DataLength and DataOffset. */
        uint16_t fid = params[6] | (params[7] << 8);
        uint16_t data_length = params[16] | (params[17] << 8);
        uint16_t data_offset = params[18] | (params[19] << 8);
        if (data_length == 0)
            return;
        /* DataOffset is the offset from the start of the SMB header (i.e.
         * msg) to the beginning of the data.  Sanity check before
         * indexing. */
        if (data_offset >= len)
            return;
        if ((size_t)data_offset + data_length > len)
            return;
        const uint8_t *data = msg + data_offset;
        /* For SMB1 write we do not track file offset, append sequentially. */
        uint64_t offset = 0; /* ignoring file offset */
        uint8_t file_id[16];
        create_file_id_smb1(conn, fid, file_id);
        write_file_chunk(file_id, offset, data, data_length);
    } else if (command == SMB1_COM_WRITE) {
        /* SMB_COM_WRITE (0x0B) has a shorter parameter block.  Expect WordCount = 5. */
        if (word_count < 5)
            return;
        uint16_t fid = params[0] | (params[1] << 8);
        uint16_t count = params[2] | (params[3] << 8);
        if (count == 0)
            return;
        /* For the simple SMB_COM_WRITE, data follows immediately after ByteCount. */
        const uint8_t *data = data_base;
        size_t data_len = count;
        if (data_len > byte_count)
            data_len = byte_count;
        uint64_t offset = 0;
        uint8_t file_id[16];
        create_file_id_smb1(conn, fid, file_id);
        write_file_chunk(file_id, offset, data, data_len);
    }
    /* SMB1 read requests/responses and other commands are not handled. */
}

/* Feed SMB bytes into stream buffer and process complete NBSS PDUs.  This
 * function dispatches SMB2/3 and SMB1 messages to the appropriate parser.
 */
static void smb_feed_bytes(connection_t *conn, int dir, const uint8_t *data, size_t len) {
    smb_stream_t *s = &conn->smb[dir];
    /* Append to buffer */
    ensure_capacity(s, s->buf_len + len);
    memcpy(s->buf + s->buf_len, data, len);
    s->buf_len += len;
    /* Process messages */
    size_t pos = 0;
    while (s->buf_len - pos >= 4) {
        /* NBSS header: 1 byte type, 3 bytes length (big‑endian) */
        uint8_t nbss_type = s->buf[pos];
        uint32_t nbss_len = (s->buf[pos + 1] << 16) | (s->buf[pos + 2] << 8) | s->buf[pos + 3];
        size_t total_len = 4 + nbss_len;
        if (s->buf_len - pos < total_len)
            break; /* wait for more data */
        const uint8_t *msg = s->buf + pos + 4;
        size_t msg_len = nbss_len;
        /* Determine SMB version by checking the first byte of the message. */
        if (msg_len >= 4) {
            if (msg[0] == 0xFE) {
                /* SMB2/3 classic header */
                parse_smb2_message(conn, dir, msg, msg_len);
            } else if (msg[0] == 0xFF) {
                /* SMB1 */
                parse_smb1_message(conn, dir, msg, msg_len);
            } else if (msg[0] == 0xFD || msg[0] == 0xFC) {
                /* SMB3 transform or compression header.  Skip as unsupported. */
            }
        }
        pos += total_len;
    }
    /* remove processed bytes from buffer */
    if (pos > 0) {
        memmove(s->buf, s->buf + pos, s->buf_len - pos);
        s->buf_len -= pos;
    }
}

/* Feed TCP payload into reassembly and eventually into SMB parser. */
static void feed_tcp_payload(connection_t *conn, int dir, uint32_t seq, const uint8_t *payload, size_t len) {
    tcp_stream_t *ts = &conn->tcp[dir];
    if (len == 0)
        return;
    if (!ts->has_next_seq) {
        ts->next_seq = seq + len;
        ts->has_next_seq = 1;
        smb_feed_bytes(conn, dir, payload, len);
        return;
    }
    if (seq == ts->next_seq) {
        ts->next_seq += len;
        smb_feed_bytes(conn, dir, payload, len);
    } else {
        /* out‑of‑order segment: drop */
    }
}

/* Packet handler invoked by pcap_loop. */
static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user; /* unused */
    /* Expect Ethernet */
    if (h->caplen < 14)
        return;
    uint16_t eth_type = (bytes[12] << 8) | bytes[13];
    if (eth_type != 0x0800)
        return; /* not IPv4 */
    const struct ip *ip = (const struct ip *)(bytes + 14);
    if (ip->ip_p != IPPROTO_TCP)
        return;
    uint32_t ip_hdr_len = ip->ip_hl * 4;
    const struct tcphdr *tcp = (const struct tcphdr *)((const uint8_t *)ip + ip_hdr_len);
    size_t ip_len = ntohs(ip->ip_len);
    size_t tcp_hdr_len = tcp->th_off * 4;
    /* Validate sizes */
    if (ip_len < ip_hdr_len + tcp_hdr_len)
        return;
    size_t payload_len = ip_len - ip_hdr_len - tcp_hdr_len;
    const uint8_t *payload = (const uint8_t *)tcp + tcp_hdr_len;
    uint16_t src_port = ntohs(tcp->th_sport);
    uint16_t dst_port = ntohs(tcp->th_dport);
    /* Filter: keep only if either endpoint uses port 445 or 139 */
    if (src_port != 445 && src_port != 139 && dst_port != 445 && dst_port != 139)
        return;
    /* Determine connection key and direction */
    conn_key_t key;
    memset(&key, 0, sizeof(key));
    int dir;
    if ((src_port == 445 || src_port == 139) && (dst_port != 445 && dst_port != 139)) {
        /* server→client */
        key.cli_ip = ip->ip_dst.s_addr;
        key.cli_port = dst_port;
        key.srv_ip = ip->ip_src.s_addr;
        key.srv_port = src_port;
        dir = 1;
    } else if ((dst_port == 445 || dst_port == 139) && (src_port != 445 && src_port != 139)) {
        /* client→server */
        key.cli_ip = ip->ip_src.s_addr;
        key.cli_port = src_port;
        key.srv_ip = ip->ip_dst.s_addr;
        key.srv_port = dst_port;
        dir = 0;
    } else {
        /* Both ports are either 445/139 or neither.  Skip ambiguous cases. */
        return;
    }
    connection_t *conn = get_connection(&key);
    /* Sequence number from TCP header */
    uint32_t seq = ntohl(tcp->th_seq);
    feed_tcp_payload(conn, dir, seq, payload, payload_len);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pcap_file> <output_dir>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *pcap_file = argv[1];
    output_dir = argv[2];
    /* ensure output directory exists */
    if (access(output_dir, F_OK) != 0) {
        if (mkdir(output_dir, 0755) != 0) {
            perror("mkdir");
            return EXIT_FAILURE;
        }
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }
    /* Only Ethernet is supported */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Unsupported link type: %d\n", pcap_datalink(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }
    /* Process packets */
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }
    pcap_close(handle);
    /* Close open files */
    for (file_ctx_t *ctx = open_files; ctx; ctx = ctx->next) {
        fflush(ctx->fp);
        fclose(ctx->fp);
    }
    /* Free pending reads and connection buffers */
    for (connection_t *c = connections; c; c = c->next) {
        for (int i = 0; i < 2; i++) {
            free(c->smb[i].buf);
            pending_read_t *pr = c->smb[i].pending;
            while (pr) {
                pending_read_t *next = pr->next;
                free(pr);
                pr = next;
            }
        }
    }
    return EXIT_SUCCESS;
}
