#!/bin/sh
# CI helper — runs INSIDE a per-kernel VM. Loads every built BPF object with
# the vendored static veristat and fails if the running kernel's verifier
# rejects any program. Driven by .github/workflows/kernel-matrix.yml, which
# boots each kernel with cilium's little-vm-helper and mounts the project at
# /host; the workflow stages the static veristat into bin/ before booting.
#
#   sh build/verify-kernel.sh [bpf-object ...]   (default: bin/*.bpf.o)
#
# apiwatch links one object per bpf/<name>/ directory (socket, ssl, ssl_ex,
# rustls), so the default is the whole set:
# veristat takes several objects in one run and names the file in each row.
#
# Set OUT_CSV=<path> to also write a machine-readable result (file,prog,verdict,
# insns,states) — the workflow points it at the mounted workspace so the runner
# can render a summary table from it after the VM exits.
#
# Why parse output instead of trusting the exit code: veristat returns 0 even
# when a program fails to load — a rejected program shows up as a VERDICT of
# "failure" in its table, not as a non-zero status. So the gate reads the verdict
# column. (veristat only exits non-zero on infra errors: missing file, OOM, etc.)

set -eu

if [ $# -gt 0 ]; then
	OBJS="$*"
else
	OBJS="$(ls bin/*.bpf.o 2>/dev/null || true)"
fi
VERISTAT="${VERISTAT:-./bin/veristat}"
# verdict LAST so the gate below can match it at end-of-line. veristat's CSV
# header uses each stat's canonical name, so the columns come out as
# file_name,prog_name,total_insns,total_states,verdict.
COLS="file,prog,insns,states,verdict"

[ -x "$VERISTAT" ] || { echo "error: veristat not found/executable at $VERISTAT" >&2; exit 1; }
[ -n "$OBJS" ]     || { echo "error: no BPF objects found (bin/*.bpf.o) — run 'make bpf' first" >&2; exit 1; }
for o in $OBJS; do
	[ -f "$o" ] || { echo "error: BPF object not found at $o" >&2; exit 1; }
done

KREL="$(uname -r)"
echo ">> kernel $KREL: loading $OBJS"

# Human-readable table for the console log (full default columns).
# shellcheck disable=SC2086
"$VERISTAT" $OBJS || true

# Machine-readable pass: the verdict column is the gate; the rest feeds the
# workflow's summary table.
# shellcheck disable=SC2086
csv="$("$VERISTAT" -o csv -e "$COLS" $OBJS)"
if [ -n "${OUT_CSV:-}" ]; then
	mkdir -p "$(dirname "$OUT_CSV")"
	printf '%s\n' "$csv" > "$OUT_CSV"
fi

# Drop the header row; fail if any program's verdict is not "success".
# Before failing, reload just the rejected objects in verbose mode so the
# verifier's own explanation lands in the CI log — the first pass runs at
# log level 0 and only reports the verdict. The log is rotated to its tail
# (that is where the rejection reason is), bounded so a long program's
# trace does not swamp the job output.
failed="$(printf '%s\n' "$csv" | tail -n +2 | grep ',failure$' | cut -d, -f1 | sort -u || true)"
if [ -n "$failed" ]; then
	objs=""
	for f in $failed; do
		for o in $OBJS; do
			[ "$(basename "$o")" = "$f" ] && objs="$objs $o"
		done
	done
	echo ">> verifier log for the rejected object(s):$objs"
	# shellcheck disable=SC2086
	"$VERISTAT" -v -l1 --log-size=65536 $objs 2>&1 | grep -v '^\s*$' | tail -n 200 || true
	echo "::error::BPF verifier rejected a program on kernel $KREL" >&2
	exit 1
fi

echo ">> all programs loaded on kernel $KREL"
