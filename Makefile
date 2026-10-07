# apiwatch build.
#
#   make           compile every bpf/<name>/ directory into bin/<name>.bpf.o
#   make veristat  load the objects and let this kernel's verifier judge them
#   make clean-bpf
#
# `yeet run github:yeet-src/apiwatch` runs `make` for you, so the default
# goal leaves the project runnable. There is no bundle step: src/main.js
# imports its modules by relative path and yeet runs it as is.
#
# clang and bpftool come from the pinned static toolchain resolved by
# build/toolchain.mk, fetched once into a shared per-machine cache, so the
# build needs no system C or BPF toolchain; only `make` itself.

.DEFAULT_GOAL := bpf

include build/toolchain.mk
include build/bpf.mk
