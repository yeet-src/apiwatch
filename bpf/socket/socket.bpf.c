/* The socket tap: plaintext capture at tcp_sendmsg / tcp_recvmsg for the
 * connections you point it at.
 *
 * Everything here is a kernel-global fentry/fexit, so this object always
 * loads — there is no uprobe in it to fail an attach. That is why it is
 * kept apart from the TLS taps (start() rejects an object with an
 * unattached uprobe): a process with no OpenSSL must not be able to take
 * plain-HTTP capture down with it.
 *
 * tcp_sendmsg carries what a process sends, in the user iovec, at entry;
 * tcp_recvmsg's buffer is filled by return, so the entry stashes the
 * buffer and the exit copies it. Both are gated in the kernel by the
 * filter maps below: an empty filter emits nothing, so an idle tap costs
 * a few hash lookups per socket call and no ring-buffer traffic.
 *
 * This sees what is plaintext on the wire — HTTP on port 80, a service
 * behind a TLS-terminating proxy, anything on localhost. A connection
 * the process encrypts in-process is ciphertext here; the TLS taps
 * (bpf/ssl, bpf/ssl_ex, bpf/gotls, bpf/rustls) read those at the library
 * boundary instead. Which connections exist, and whose they are, comes
 * from the system graph rather than from here.
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

#include "events.h"

char LICENSE[] SEC("license") = "GPL";

/* ---- filter ------------------------------------------------------------
 *
 * A socket call is captured when the connection is not on an ignored
 * port and either capture_all is set, the pid is focused, or one of its
 * two ports is. Ports are keyed as __u32 so the JS side writes plain
 * numbers. `ignore_ports` is for the tool's own traffic — the WebSocket
 * that carries this UI would otherwise capture itself.
 */
volatile __u8 capture_all; /* .bss, patched from JS */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} focus_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} focus_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 64);
} ignore_ports SEC(".maps");

static __always_inline int wanted(struct sock *sk, __u32 pid)
{
    __u32 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u32 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (bpf_map_lookup_elem(&ignore_ports, &sport) || bpf_map_lookup_elem(&ignore_ports, &dport))
        return 0;
    if (capture_all)
        return 1;
    if (bpf_map_lookup_elem(&focus_pids, &pid))
        return 1;
    if (bpf_map_lookup_elem(&focus_ports, &sport) || bpf_map_lookup_elem(&focus_ports, &dport))
        return 1;
    return 0;
}

/* ---- capture --------------------------------------------------------------- */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} frames SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct read_args);
    __uint(max_entries, 10240);
} active_reads SEC(".maps");

/* struct iov_iter was reshaped in 6.4 (the iovec pointer became `__iov`,
 * and the enum was renumbered with ITER_UBUF first), so every read of it
 * goes through CO-RE against the running kernel. The old spelling needs a
 * flavour; the guard is a CO-RE constant, so the branch for the layout
 * we did not load on is pruned before the verifier sees it. */
struct iov_iter___old {
    const struct iovec *iov;
};

/* vmlinux.h is generated from the build host's BTF, so a member only one
 * layout has cannot be named through `struct iov_iter`: built on 6.1 there
 * is no `__iov` to name. The 6.4 spellings go through this flavour too;
 * libbpf drops the ___suffix and matches members by name, through the
 * anonymous unions 6.4 put them in. BTF carries no __user, so `ubuf` is a
 * plain pointer here. */
struct iov_iter___new {
    const struct iovec *__iov;
    void *ubuf;
} __attribute__((preserve_access_index));

/* ITER_UBUF the same way: libbpf drops the ___suffix from the enum and its
 * enumerator, so this resolves against the running kernel's iter_type and
 * the 0 is never used. ITER_UBUF and `ubuf` came in together (6.1 already
 * has both), so this one guard also covers the `ubuf` read. */
enum iter_type___new {
    ITER_UBUF___new = 0,
};

static __always_inline int iter_is_ubuf(__u8 type)
{
    return bpf_core_enum_value_exists(enum iter_type___new, ITER_UBUF___new) &&
           type == bpf_core_enum_value(enum iter_type___new, ITER_UBUF___new);
}

static __always_inline const struct iovec *iter_iov(struct iov_iter *it)
{
    if (bpf_core_field_exists(struct iov_iter___old, iov))
        return BPF_CORE_READ((struct iov_iter___old *) it, iov);
    return BPF_CORE_READ((struct iov_iter___new *) it, __iov);
}

static __always_inline struct iov_iter *msg_iter(struct msghdr *msg)
{
    return (void *) msg + bpf_core_field_offset(struct msghdr, msg_iter);
}

/* Where the iterator will write next, and how much room is there.
 * ITER_UBUF is a single buffer; ITER_IOVEC an array whose first element
 * we take. Either way `iov_offset` says how far into that buffer the
 * kernel already is: a syscall can reach tcp_recvmsg more than once
 * with the same msghdr, and the second round lands after the first
 * (seen on 7.2: one recv of 210 bytes came as rounds of 192 and 18).
 * Anything else (kvec, bvec: kernel-internal) is not a user payload. */
static __always_inline int iter_first(struct msghdr *msg, __u64 *base, __u64 *len)
{
    struct iov_iter *it = msg_iter(msg);
    __u8 type = BPF_CORE_READ(it, iter_type);
    __u64 skip = BPF_CORE_READ(it, iov_offset);

    if (iter_is_ubuf(type)) {
        *base = (__u64) BPF_CORE_READ((struct iov_iter___new *) it, ubuf) + skip;
        *len = BPF_CORE_READ(it, count);
        return *base != 0;
    }
    if (type != bpf_core_enum_value(enum iter_type, ITER_IOVEC))
        return 0;

    const struct iovec *iov = iter_iov(it);
    struct iovec v;
    if (bpf_probe_read_kernel(&v, sizeof(v), iov))
        return 0;
    if (skip > v.iov_len)
        return 0;
    *base = (__u64) v.iov_base + skip;
    *len = v.iov_len - skip;
    return *base != 0;
}

/* int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size): the
 * bytes are in the user iovec at entry. A single send is often several
 * iovec segments (a header block and a body written with one writev),
 * so each segment is emitted on its own and the decoder concatenates
 * per connection. */
SEC("fentry/tcp_sendmsg")
int BPF_PROG(on_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    if ((long) size <= 0)
        return 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!wanted(sk, pid))
        return 0;

    struct iov_iter *it = msg_iter(msg);
    __u8 type = BPF_CORE_READ(it, iter_type);

    if (iter_is_ubuf(type)) {
        emit_data(&frames, (__u64) sk, (__u64) BPF_CORE_READ((struct iov_iter___new *) it, ubuf),
                  (__u32) BPF_CORE_READ(it, count),
                  DIR_WRITE, TRANSPORT_TCP, sk, 0);
        return 0;
    }
    if (type != bpf_core_enum_value(enum iter_type, ITER_IOVEC))
        return 0;

    const struct iovec *iov = iter_iov(it);
    __u64 nr = BPF_CORE_READ(it, nr_segs);
#pragma unroll
    for (int i = 0; i < 8; i++) {
        if ((__u64) i >= nr)
            break;
        struct iovec v;
        if (bpf_probe_read_kernel(&v, sizeof(v), &iov[i]))
            break;
        if (v.iov_len)
            emit_data(&frames, (__u64) sk, (__u64) v.iov_base, (__u32) v.iov_len, DIR_WRITE, TRANSPORT_TCP, sk, 0);
    }
    return 0;
}

/* int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, ...):
 * the destination is filled by return. Stash (sk, where the iterator
 * will write, how much room) at entry; the exit reads the return count
 * with the helper — the arity changed in 5.19 — and copies min(ret,
 * room). `flags` rides along so the record can say a read was a peek.
 *
 * Two things that were wrong here once: the iterator's `iov_offset` was
 * ignored, so a second tcp_recvmsg round inside one syscall re-read the
 * start of the buffer; and the int return was taken zero-extended, so
 * -EAGAIN became a huge count capped to the room — a record full of
 * whatever the buffer held before. Both showed up as a response head
 * where curl's body should have been. */
SEC("fentry/tcp_recvmsg")
int BPF_PROG(on_recvmsg_enter, struct sock *sk, struct msghdr *msg, size_t len, int flags)
{
    __u64 id = bpf_get_current_pid_tgid();
    if (!wanted(sk, id >> 32))
        return 0;
    struct read_args a = { .conn = (__u64) sk, .flags = (__u64) (__u32) flags };
    if (!iter_first(msg, &a.buf, &a.nread))
        return 0;
    bpf_map_update_elem(&active_reads, &id, &a, BPF_ANY);
    return 0;
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(on_recvmsg_exit, struct sock *sk)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct read_args *a = bpf_map_lookup_elem(&active_reads, &id);
    if (!a)
        return 0;
    __u64 buf = a->buf, cap = a->nread, flags = a->flags;
    bpf_map_delete_elem(&active_reads, &id);

    __u64 ret = 0;
    if (bpf_get_func_ret(ctx, &ret))
        return 0;
    /* The int return arrives zero-extended: -EAGAIN is 0xfffffff5 here,
     * a very large count, unless it is taken as the int it was. */
    long n = (int) ret;
    if (n <= 0)
        return 0;
    if ((__u64) n > cap)
        n = (long) cap;
    emit_data(&frames, (__u64) sk, buf, (__u32) n, DIR_READ, TRANSPORT_TCP, sk, (__u8) flags);
    return 0;
}
