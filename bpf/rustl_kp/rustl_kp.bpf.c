/* The rustls tap with its two socket hooks as kprobes, for kernels where
 * fentry cannot attach (arm64 before 6.4). The uprobes are unchanged.
 * Same source, same program and map names; see bpf/include/hooks.h.
 * Named to fit libbpf's 8-character object prefix. */
#define APIWATCH_KPROBE
#include "../rustls/rustls.bpf.c"
