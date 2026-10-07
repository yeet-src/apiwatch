/* The OpenSSL classic-API tap: SSL_read / SSL_write.
 *
 * This is the boundary Node, Rust native-tls, uSockets and most C code
 * cross — the byte-count API. CPython and anything else on the OpenSSL
 * 1.1.1+ `_ex` pair is invisible here and handled by bpf/ssl_ex, kept
 * separate because BoringSSL and older OpenSSL lack those symbols and a
 * missing symbol fails the whole object (see tap.h).
 *
 *   SSL_write(ssl, buf, num)  plaintext is in `buf` at entry
 *   SSL_read(ssl, buf, num)   `buf` is filled by return; the count is the
 *                             return value, so entry stashes the buffer
 *                             and the return probe copies it
 *
 * The SSL* is stable for the connection's life and is the connection id.
 */

#define BPF_NO_KFUNC_PROTOTYPES

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "tap.h"

char LICENSE[] SEC("license") = "GPL";

/* int SSL_write(SSL *ssl, const void *buf, int num) */
SEC("uprobe")
int BPF_KPROBE(ssl_write, void *ssl, const void *buf, int num)
{
    if (num > 0)
        emit((__u64) ssl, (__u64) buf, (__u32) num, DIR_WRITE);
    return 0;
}

/* int SSL_read(SSL *ssl, void *buf, int num) */
SEC("uprobe")
int BPF_KPROBE(ssl_read_enter, void *ssl, void *buf, int num)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct read_args a = { .conn = (__u64) ssl, .buf = (__u64) buf, .nread = 0 };
    bpf_map_update_elem(&active_reads, &id, &a, BPF_ANY);
    /* The recvmsg that fills this buffer happens inside the call. */
    note_conn((__u64) ssl);
    return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(ssl_read_exit, int ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct read_args *a = bpf_map_lookup_elem(&active_reads, &id);
    if (!a)
        return 0;
    __u64 ssl = a->conn, buf = a->buf;
    bpf_map_delete_elem(&active_reads, &id);
    if (ret > 0)
        emit(ssl, buf, (__u32) ret, DIR_READ);
    return 0;
}
