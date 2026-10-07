/* The OpenSSL classic-API tap with its two socket hooks as kprobes, for
 * kernels where fentry cannot attach (arm64 before 6.4). The uprobes are
 * unchanged. Same source, same program and map names; see
 * bpf/include/hooks.h. */
#define APIWATCH_KPROBE
#include "../ssl/ssl.bpf.c"
