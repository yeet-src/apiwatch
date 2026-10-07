/* Kernel-function hooks: one source, two builds.
 *
 * fentry/fexit is the default: BTF-typed, and cheaper than a kprobe. It
 * needs ftrace direct calls, which arm64 only has from 6.4, so on an
 * older arm64 kernel every fentry loads and then fails to attach with
 * -ENOTSUPP. For those kernels the same source is compiled a second time
 * with APIWATCH_KPROBE defined (the one-line units in bpf/sock_kp,
 * bpf/ssl_kp, bpf/sslex_kp and bpf/rustl_kp), and each entry hook below
 * becomes a kprobe. Program and map names are the same in both builds, so
 * the loaders bind either one; src/lib/capture.js picks once at startup.
 *
 * A kprobe's arguments are bare registers, not BTF pointers, so whatever
 * is read through them must go through BPF_CORE_READ or a probe read.
 * The one return hook (tcp_recvmsg, in bpf/socket) is spelled out where
 * it is used: fexit and a kretprobe differ in more than the section name.
 *
 * Include after the libbpf headers.
 */
#pragma once

#ifdef APIWATCH_KPROBE
#define HOOK_ENTRY(fn)        SEC("kprobe/" #fn)
#define HOOK_PROG(name, ...)  BPF_KPROBE(name, ##__VA_ARGS__)
#else
#define HOOK_ENTRY(fn)        SEC("fentry/" #fn)
#define HOOK_PROG(name, ...)  BPF_PROG(name, ##__VA_ARGS__)
#endif
