/* The rustls tap: plaintext at rustls's own boundary.
 *
 * rustls is pure Rust — no OpenSSL, no C ABI. Its boundary functions are
 * generic, monomorphised, and exported under mangled names that carry a
 * per-build codegen hash, so the exact symbol differs per binary. The
 * loader attaches with `match: "regex"` against the demangled names (see
 * app/lib/probes/tlscore.js), which is why nothing here names a symbol.
 *
 *   egress   <ConnectionCommon<T> as PlaintextSink>::write(&mut self, buf: &[u8])
 *            a &[u8] is a fat pointer, so the args land as
 *            (self, buf.ptr, buf.len) — captured at entry.
 *   ingress  CommonState::take_received_plaintext(&mut self, bytes: Vec<u8>)
 *            despite the name this *receives* the just-decrypted app data;
 *            the Vec is passed indirectly, `arg1` pointing at 24 bytes laid
 *            out {cap @ +0, ptr @ +8, len @ +16} (observed, not guaranteed —
 *            verify against a new rustls).
 *
 * `&mut self` is the same CommonState pointer on both sides, so egress
 * and ingress share one connection id. Rust threads do not migrate mid
 * call, so no return probe and no goroutine trick is needed.
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

/* fn write(&mut self, buf: &[u8]) -> io::Result<usize> */
SEC("uprobe")
int BPF_KPROBE(rust_tls_write, void *conn, void *ptr, __u64 len)
{
    if ((long) len > 0) {
        note_conn((__u64) conn);
        emit((__u64) conn, (__u64) ptr, (__u32) len, DIR_WRITE);
    }
    return 0;
}

/* fn take_received_plaintext(&mut self, bytes: Vec<u8>) */
SEC("uprobe")
int BPF_KPROBE(rust_tls_read, void *conn, void *vec)
{
    __u64 ptr = 0, len = 0;
    if (bpf_probe_read_user(&ptr, sizeof(ptr), (const void *) ((__u64) vec + 8)) ||
        bpf_probe_read_user(&len, sizeof(len), (const void *) ((__u64) vec + 16)))
        return 0;
    if (len > 0 && len < (1u << 20))
        emit((__u64) conn, ptr, (__u32) len, DIR_READ);
    return 0;
}
