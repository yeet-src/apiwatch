/* The records every httpscope object ships up, and the one bounded copy
 * routine that fills them.
 *
 * Two kinds of object capture application bytes — the socket tap (plain
 * HTTP at tcp_sendmsg/tcp_recvmsg) and the TLS taps (plaintext at a
 * library's read/write boundary) — and both emit the same `data_event`,
 * so one decoder on the JS side serves every transport. Connection
 * discovery is not in the kernel at all: the system graph's tcp tables
 * joined to each process's socket fds give that (app/lib/probes/conns.js). The taps are separate
 * loadable objects (a uprobe that fails to attach would take the
 * always-loadable socket probes down with it), so this header is shared
 * as source: each object carries its own copy of the types in its BTF,
 * under the same names the JS binds to.
 *
 * Include after vmlinux.h and the libbpf helpers.
 */
#pragma once

/* Bytes captured per segment. The ring-buffer record is reserved at the
 * full struct size whatever `len` is, so this is the per-event cost; a
 * call larger than one segment is split across up to MAX_SEGS records
 * (`off` says where each lands) rather than truncated at 4 KiB. */
#define CHUNK    4096
#define CAP_MASK 0x0fff  /* a copy length the verifier can bound: at most 4095 */
#define MAX_SEGS 8       /* 8 × 4095 ≈ 32 KiB captured from one call */

#define DIR_READ  0      /* bytes the process received */
#define DIR_WRITE 1      /* bytes the process sent */

#define TRANSPORT_TCP  0 /* plain TCP: tcp_sendmsg / tcp_recvmsg */
#define TRANSPORT_TLS  1 /* a TLS library's plaintext boundary */
#define TRANSPORT_WIRE 2 /* TCP payload off the wire at TCX, reassembled on the host */

/* vmlinux.h carries no socket.h constants. */
#define AF_INET  2
#define AF_INET6 10

/* One captured window of application bytes. `conn` is the opaque
 * per-connection id: the `struct sock *` for TCP, the SSL pointer, Go Conn or
 * rustls state pointer for a TLS tap. The flow fields are filled when the tap
 * knows the socket (TCP) and zero otherwise; a TLS tap reports its
 * connection's flow separately through a `peer_event`. */
struct data_event {
    __u64 ts;
    __u64 conn;
    __u32 pid;
    __u32 tid;
    __u32 len;       /* bytes in the whole call */
    __u32 off;       /* where this segment starts within the call */
    __u32 cap_len;   /* bytes copied into data[] */
    __u8  dir;       /* DIR_READ | DIR_WRITE */
    __u8  transport; /* TRANSPORT_TCP | TRANSPORT_TLS */
    __u8  family;    /* AF_INET | AF_INET6 | 0 = unknown */
    __u8  flags;     /* low byte of recvmsg flags for a TCP read (MSG_PEEK 2, MSG_TRUNC 0x20); else 0 */
    __u16 sport;     /* host order; the local port */
    __u16 dport;     /* host order; the remote port */
    __u8  saddr[16]; /* v4 in the first 4 bytes */
    __u8  daddr[16];
    __u8  data[CHUNK];
};

/* A TLS connection's socket, learned by correlation: the thread that
 * just entered SSL_write is the thread about to call tcp_sendmsg. */
struct peer_event {
    __u64 ts;
    __u64 conn;
    __u64 sk;
    __u32 pid;
    __u8  family;
    __u8  _pad[3];
    __u16 sport;
    __u16 dport;
    __u8  saddr[16];
    __u8  daddr[16];
};

/* One TCP segment's payload as it crossed a network device (bpf/wire).
 * No process context exists there, so there is no pid; the flow is as
 * the packet spelled it (src → dst), and `seq` lets the host put
 * segments back in order and drop retransmits. A GSO super-segment can
 * be 64 KiB, so a packet spans up to WIRE_SEGS records. A record with
 * `len` 0 carries a SYN/FIN/RST so the host can open and close flows. */
#define WIRE_SEGS 16
#define HOOK_INGRESS 0
#define HOOK_EGRESS  1
#define TCPF_FIN 0x01
#define TCPF_SYN 0x02
#define TCPF_RST 0x04
#define TCPF_PSH 0x08
#define TCPF_ACK 0x10

struct wire_event {
    __u64 ts;
    __u32 ifindex;
    __u8  hook;      /* HOOK_INGRESS | HOOK_EGRESS */
    __u8  family;
    __u8  tcpflags;  /* TCPF_* */
    __u8  _pad;
    __u16 sport;     /* host order, as in the packet */
    __u16 dport;
    __u8  saddr[16];
    __u8  daddr[16];
    __u32 seq;       /* host order */
    __u32 ack;
    __u32 len;       /* payload bytes in the packet */
    __u32 off;
    __u32 cap_len;
    __u8  data[CHUNK];
};

/* Anchors, so each struct appears in the object's BTF by name — the
 * loader decodes ring-buffer records by `btf_struct`, and a type only
 * reached through the `void *` a reserve returns is otherwise never
 * emitted. */
__attribute__((used)) static const struct data_event __data_event_anchor;
__attribute__((used)) static const struct peer_event __peer_event_anchor;
__attribute__((used)) static const struct wire_event __wire_event_anchor;

/* A read call's arguments, carried from its entry to its return: the
 * buffer is only filled once the call comes back. Keyed per thread (or
 * per goroutine, for Go). `nread` is either the `size_t *` an `_ex`
 * variant reports through, or, for the socket tap, the first iovec's
 * length — a cap on how much of the return count lands in `buf`. */
struct read_args {
    __u64 conn;
    __u64 buf;
    __u64 nread;
    __u64 flags; /* the recvmsg flags, for the socket tap */
};

/* The socket's addressing, read through CO-RE so the field offsets
 * come from the running kernel. `saddr`/`daddr` point at 16 bytes. */
static __always_inline void read_flow(struct sock *sk, __u8 *family, __u16 *sport, __u16 *dport,
                                      void *saddr, void *daddr)
{
    __u16 fam = BPF_CORE_READ(sk, __sk_common.skc_family);
    *family = (__u8) fam;
    *sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    *dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    __builtin_memset(saddr, 0, 16);
    __builtin_memset(daddr, 0, 16);
    if (fam == AF_INET6) {
        bpf_core_read(saddr, 16, &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_core_read(daddr, 16, &sk->__sk_common.skc_v6_daddr);
    } else {
        bpf_core_read(saddr, 4, &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(daddr, 4, &sk->__sk_common.skc_daddr);
    }
}

/* Copy `len` bytes of user memory at `buf` into `rb` as one or more
 * `data_event` segments. Stops early if the ring is full or a page is
 * not resident — the JS side sees the hole as `off + cap_len < len` on
 * the last record and resyncs at the next message boundary. */
static __always_inline void emit_data(void *rb, __u64 conn, __u64 buf, __u32 len, __u8 dir,
                                      __u8 transport, struct sock *sk, __u8 flags)
{
    if (len == 0)
        return;

    __u64 id = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    __u8 family = 0;
    __u16 sport = 0, dport = 0;
    __u8 saddr[16] = {}, daddr[16] = {};
    if (sk)
        read_flow(sk, &family, &sport, &dport, saddr, daddr);

#pragma unroll
    for (int i = 0; i < MAX_SEGS; i++) {
        __u32 off = (__u32) i * CAP_MASK;
        if (off >= len)
            break;

        struct data_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
        if (!e)
            return;

        e->ts = ts;
        e->conn = conn;
        e->pid = id >> 32;
        e->tid = (__u32) id;
        e->len = len;
        e->off = off;
        e->dir = dir;
        e->transport = transport;
        e->family = family;
        e->flags = flags;
        e->sport = sport;
        e->dport = dport;
        __builtin_memcpy(e->saddr, saddr, 16);
        __builtin_memcpy(e->daddr, daddr, 16);

        __u32 cap = len - off;
        if (cap > CAP_MASK)
            cap = CAP_MASK;
        e->cap_len = cap;

        /* Clamp, then mask, so the verifier sees a bounded length. */
        barrier_var(cap);
        cap &= CAP_MASK;
        if (cap == 0 || bpf_probe_read_user(e->data, cap, (const void *) (buf + off))) {
            bpf_ringbuf_discard(e, 0);
            return;
        }
        bpf_ringbuf_submit(e, 0);
    }
}
