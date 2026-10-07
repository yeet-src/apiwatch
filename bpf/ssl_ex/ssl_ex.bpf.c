/* The OpenSSL `_ex` tap: SSL_read_ex / SSL_write_ex (OpenSSL 1.1.1+).
 *
 * Same plaintext, same records, different symbols and a different way of
 * reporting the count: these return a 0/1 status and put the byte count
 * in a `size_t *` out-parameter. CPython's _ssl calls exactly this pair,
 * so Python's requests/urllib/httpx are visible only here. Its own object
 * because the symbols are absent from BoringSSL and pre-1.1.1 OpenSSL,
 * and one unattachable uprobe fails an object (see tap.h).
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

/* int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written):
 * `num` is what the application handed over — the whole message — and
 * a short write only means fewer bytes reached the wire this call. */
SEC("uprobe")
int BPF_KPROBE(ssl_write_ex, void *ssl, const void *buf, unsigned long num)
{
    if (num > 0)
        emit((__u64) ssl, (__u64) buf, (__u32) num, DIR_WRITE);
    return 0;
}

/* int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes) */
SEC("uprobe")
int BPF_KPROBE(ssl_read_ex_enter, void *ssl, void *buf, unsigned long num, void *readbytes)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct read_args a = { .conn = (__u64) ssl, .buf = (__u64) buf, .nread = (__u64) readbytes };
    bpf_map_update_elem(&active_reads, &id, &a, BPF_ANY);
    note_conn((__u64) ssl);
    return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(ssl_read_ex_exit, int ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct read_args *a = bpf_map_lookup_elem(&active_reads, &id);
    if (!a)
        return 0;
    __u64 ssl = a->conn, buf = a->buf, nread = a->nread;
    bpf_map_delete_elem(&active_reads, &id);

    /* 0 means failure or retry, and *readbytes is then untouched. */
    if (ret <= 0 || !nread)
        return 0;
    __u64 n = 0;
    if (bpf_probe_read_user(&n, sizeof(n), (const void *) nread))
        return 0;
    if (n > 0)
        emit(ssl, buf, (__u32) n, DIR_READ);
    return 0;
}
