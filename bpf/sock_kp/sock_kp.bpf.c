/* The socket tap with kprobes in place of fentry/fexit, for kernels where
 * fentry cannot attach (arm64 before 6.4). Same source, same program and
 * map names; see bpf/include/hooks.h. The directory name is the object's
 * name, and libbpf keeps only its first 8 characters when it names the
 * data section the loader binds (sock_kp.bss). */
#define APIWATCH_KPROBE
#include "../socket/socket.bpf.c"
