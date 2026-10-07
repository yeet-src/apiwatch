/* What every TLS tap has in common: the maps, the focus filter, the
 * emit path, and the correlation that finds a TLS connection's socket.
 *
 * The four taps (OpenSSL classic, OpenSSL `_ex`, Go crypto/tls, rustls)
 * differ only in which symbols they hook and how a read's byte count is
 * recovered. Everything downstream of "here are (conn, buf, len, dir)"
 * is here, once. Each tap is its own loadable object because start()
 * rejects an object with an unattached uprobe, and a target offers only
 * some of these boundaries — so the taps attach independently, best
 * effort, and one missing symbol family never costs another.
 *
 * Include after vmlinux.h and the libbpf headers.
 */
#pragma once

#include "events.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} peers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct read_args);
    __uint(max_entries, 10240);
} active_reads SEC(".maps");

/* The user→kernel control path. JS writes two slots live: slot 0 a
 * connection id, slot 1 a pid. A non-zero slot restricts emission to
 * matches; zero (the default) passes everything. The check runs before
 * the ring-buffer reserve, so muted traffic costs a lookup and nothing
 * else. */
#define FOCUS_CONN 0
#define FOCUS_PID  1
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} focus SEC(".maps");

/* ---- which socket is this TLS connection on? ------------------------
 *
 * A TLS library hands us plaintext and an opaque connection pointer, and
 * nothing about the peer. But the thread that enters SSL_write is the
 * thread about to call tcp_sendmsg on that connection's socket (for a
 * socket BIO, inside the same call; for a memory BIO, on the same tick),
 * and the thread inside SSL_read is the one calling tcp_recvmsg. So the
 * tap notes (thread → conn) on the way in, and an fentry on the two
 * socket calls turns the next hit on that thread into a (conn → socket)
 * binding, emitted once per connection.
 *
 * It is a heuristic: an event loop that interleaves two connections on
 * one thread between the note and the socket call binds the wrong one.
 * The first binding wins, and the HTTP decoder's Host header is the
 * authority for naming the service anyway. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);   /* pid_tgid */
    __type(value, __u64); /* conn */
    __uint(max_entries, 4096);
} pending_conn SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);   /* conn */
    __type(value, __u64); /* sk */
    __uint(max_entries, 4096);
} bound SEC(".maps");

static __always_inline void note_conn(__u64 conn)
{
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pending_conn, &id, &conn, BPF_ANY);
}

static __always_inline void peer_hit(struct sock *sk)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *conn = bpf_map_lookup_elem(&pending_conn, &id);
    if (!conn)
        return;
    __u64 c = *conn;
    bpf_map_delete_elem(&pending_conn, &id);

    __u64 skv = (__u64) sk;
    __u64 *known = bpf_map_lookup_elem(&bound, &c);
    if (known && *known == skv)
        return;
    bpf_map_update_elem(&bound, &c, &skv, BPF_ANY);

    struct peer_event *e = bpf_ringbuf_reserve(&peers, sizeof(*e), 0);
    if (!e)
        return;
    e->ts = bpf_ktime_get_ns();
    e->conn = c;
    e->sk = skv;
    e->pid = id >> 32;
    e->_pad[0] = e->_pad[1] = e->_pad[2] = 0;
    read_flow(sk, &e->family, &e->sport, &e->dport, e->saddr, e->daddr);
    bpf_ringbuf_submit(e, 0);
}

/* Kernel-global, BTF-typed, and auto-attached with the object. Only the
 * first argument is read, so the declaration holds across kernels that
 * changed the rest of the signature. */
SEC("fentry/tcp_sendmsg")
int BPF_PROG(peer_sendmsg, struct sock *sk)
{
    peer_hit(sk);
    return 0;
}

SEC("fentry/tcp_recvmsg")
int BPF_PROG(peer_recvmsg, struct sock *sk)
{
    peer_hit(sk);
    return 0;
}

/* ---- the emit path ---------------------------------------------------- */

static __always_inline int focused(__u64 conn, __u32 pid)
{
    __u32 k_conn = FOCUS_CONN, k_pid = FOCUS_PID;
    __u64 *f_conn = bpf_map_lookup_elem(&focus, &k_conn);
    __u64 *f_pid = bpf_map_lookup_elem(&focus, &k_pid);
    if (f_conn && *f_conn && conn != *f_conn)
        return 0;
    if (f_pid && *f_pid && pid != (__u32) *f_pid)
        return 0;
    return 1;
}

static __always_inline void emit(__u64 conn, __u64 buf, __u32 len, __u8 dir)
{
    if (len == 0)
        return;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!focused(conn, pid))
        return;
    note_conn(conn);
    emit_data(&events, conn, buf, len, dir, TRANSPORT_TLS, NULL, 0);
}
