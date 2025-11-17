/*
 * smb_reassembler_port445.c
 *
 * This program demonstrates how to reconstruct files transferred over
 * SMB2 by passively sniffing only traffic on TCP port 445.  It uses
 * libpcap to read a capture file and decodes Ethernet/IPv4/TCP
 * layers, reassembles TCP streams per connection, parses SMB2
 * messages and writes file contents out to disk based on SMB2
 * FileIds.
 *
 * The code is written to satisfy an assignment where the capture
 * filter restricts traffic to TCP packets with either source or
 * destination port 445.  Despite this filter, both directions of the
 * SMB connections are preserved because one side of each connection
 * always uses port 445.  The program therefore reconstructs entire
 * files by tracking data offsets and FileIds.
 *
 * Limitations:
 *   - Only IPv4/TCP traffic is supported; IPv6 and fragmentation
 *     handling are omitted for brevity.
 *   - TCP reassembly is simplistic: out‑of‑order segments are dropped.
 *     For reliable reconstruction you should collect captures on a
 *     relatively lossless network and start capturing before the
 *     SMB session begins.
 *   - Only SMB2 READ responses and WRITE requests carry file data
 *     which this program extracts.  SMB3 encryption is not
 *     supported; encrypted payloads will appear as gibberish.
 *
 * Usage:
 *     ./smb_reassembler_port445 <pcap_file> <output_dir>
 *
 * The program iterates over all packets in the specified pcap file,
 * reconstructs any files transferred via SMB2, and writes them
 * into the specified output directory.  The filenames are derived
 * from the 16‑byte SMB2 FileId rendered in hexadecimal.
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

/* Connection key identifying one SMB TCP connection.
 * We treat the endpoint with port 445 as the server and the other
 * endpoint as the client.  For each direction we track a separate
 * TCP sequence number and SMB2 parsing state.  */
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

/* Pending READ request awaiting a response. */
typedef struct pending_read {
    uint64_t msg_id;
    uint8_t file_id[16];
    uint64_t offset;
    uint32_t length;
    struct pending_read *next;
} pending_read_t;

/* SMB2 stream state for one direction. */
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

/* Utility: Compare two connection keys. */
static int conn_key_equal(const conn_key_t *a, const conn_key_t *b) {
    return a->cli_ip == b->cli_ip && a->cli_port == b->cli_port &&
           a->srv_ip == b->srv_ip && a->srv_port == b->srv_port;
}

/* Convert IPv4 dotted decimal string to uint32_t in network byte order. */
static uint32_t ip_str_to_u32(const char *s) {
    struct in_addr addr;
    inet_pton(AF_INET, s, &addr);
    return addr.s_addr;
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

/* Utility: ensure buffer can hold at least new_cap bytes. */
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

/* Append bytes to SMB2 stream buffer and process complete messages. */
static void smb2_feed_bytes(connection_t *conn, int dir, const uint8_t *data, size_t len);

/* Write file chunk to output file identified by FileId. */
static void write_file_chunk(const uint8_t *file_id, uint64_t offset, const uint8_t *data, size_t len) {
    /* find or create file context */
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
        /* construct filename */
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

/* Handle a SMB2 WRITE request (client→server). */
static void parse_write_request(const uint8_t *body, size_t len) {
    if (len < 32)
        return;
    /* In SMB2 WRITE request: body[0:2] struct_size, body[2:4] data_offset, body[4:8] data_length,
     * body[8:16] file offset, body[24:40] FileId, body[data_offset: data_offset+data_length] data. */
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

/* Record a pending READ request (client→server). */
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

/* Handle a SMB2 READ response (server→client). */
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
    int is_response = (flags & 0x00000001) != 0; /* SMB2_FLAGS_SERVER_TO_REDIR */
    const uint8_t *body = msg + 64;
    size_t body_len = len - 64;
    /* SMB2 opcodes of interest */
    const uint16_t SMB2_READ = 0x0008;
    const uint16_t SMB2_WRITE = 0x0009;
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

/* Feed SMB2 bytes into stream buffer and parse complete SMB2 PDUs. */
static void smb2_feed_bytes(connection_t *conn, int dir, const uint8_t *data, size_t len) {
    smb_stream_t *s = &conn->smb[dir];
    /* Append to buffer */
    ensure_capacity(s, s->buf_len + len);
    memcpy(s->buf + s->buf_len, data, len);
    s->buf_len += len;
    /* Process messages */
    size_t pos = 0;
    while (s->buf_len - pos >= 4) {
        /* NBSS header: 1 byte type, 3 bytes length (big‑endian) */
        uint32_t nbss_len = (s->buf[pos + 1] << 16) | (s->buf[pos + 2] << 8) | s->buf[pos + 3];
        size_t total_len = 4 + nbss_len;
        if (s->buf_len - pos < total_len)
            break; /* wait for more data */
        const uint8_t *msg = s->buf + pos + 4;
        size_t msg_len = nbss_len;
        parse_smb2_message(conn, dir, msg, msg_len);
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
        smb2_feed_bytes(conn, dir, payload, len);
        return;
    }
    if (seq == ts->next_seq) {
        ts->next_seq += len;
        smb2_feed_bytes(conn, dir, payload, len);
    } else {
        /* out‑of‑order segment: drop */
    }
}

/* Packet handler invoked by pcap_loop. */
static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user; /* unused */
    /* expect Ethernet */
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
    /* Filter: keep only if either endpoint uses port 445 */
    if (src_port != 445 && dst_port != 445)
        return;
    /* Determine connection key and direction */
    conn_key_t key;
    memset(&key, 0, sizeof(key));
    int dir;
    if (src_port == 445 && dst_port != 445) {
        /* server→client */
        key.cli_ip = ip->ip_dst.s_addr;
        key.cli_port = dst_port;
        key.srv_ip = ip->ip_src.s_addr;
        key.srv_port = src_port;
        dir = 1;
    } else {
        /* client→server */
        key.cli_ip = ip->ip_src.s_addr;
        key.cli_port = src_port;
        key.srv_ip = ip->ip_dst.s_addr;
        key.srv_port = dst_port;
        dir = 0;
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