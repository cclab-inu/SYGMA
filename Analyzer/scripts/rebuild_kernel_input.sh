#!/usr/bin/env bash
set -euo pipefail

KSR=${KSR:-/workspace/git/linux-v5.15-analysis-src}
KOUT=${KOUT:-/workspace/git/linux-v5.15-analysis-build}
JOBS=${JOBS:-$(nproc)}
LD_BIN=${LD_BIN:-/usr/bin/ld.bfd}
HOSTLD_BIN=${HOSTLD_BIN:-/usr/bin/ld.bfd}

if [[ ! -d "$KSR" ]]; then
	echo "kernel source directory not found: $KSR" >&2
	exit 1
fi
if [[ "$KSR" == "$KOUT" ]]; then
	echo "KSR and KOUT must be different directories" >&2
	exit 1
fi

mkdir -p "$KOUT"

make -C "$KSR" mrproper
make -C "$KSR" O="$KOUT" LLVM=1 LD="$LD_BIN" HOSTLD="$HOSTLD_BIN" mrproper

# This target is intentionally unconditional. `make clean` preserves .config,
# so guarding it with `if [ ! -f "$KOUT/.config" ]` silently reuses an older
# distribution/allmod configuration and changes the configured analysis set.
make -C "$KSR" O="$KOUT" LLVM=1 LD="$LD_BIN" HOSTLD="$HOSTLD_BIN" \
	x86_64_defconfig

"$KSR/scripts/config" --file "$KOUT/.config" \
	-e SECURITY \
	-e SECURITY_PATH \
	-e BPF_SYSCALL \
	-e BPF_JIT \
	-e BPF_EVENTS \
	-e BPF_LSM \
	--set-str LSM "landlock,lockdown,yama,integrity,apparmor,bpf"

make -C "$KSR" O="$KOUT" LLVM=1 LD="$LD_BIN" HOSTLD="$HOSTLD_BIN" \
	olddefconfig

grep -E \
	'^CONFIG_(SECURITY|SECURITY_PATH|BPF_SYSCALL|BPF_JIT|BPF_EVENTS|BPF_LSM|LSM)=' \
	"$KOUT/.config"

make -C "$KSR" O="$KOUT" LLVM=1 LD="$LD_BIN" HOSTLD="$HOSTLD_BIN" \
	-j"$JOBS" all
make -C "$KSR" O="$KOUT" LLVM=1 LD="$LD_BIN" HOSTLD="$HOSTLD_BIN" \
	compile_commands.json

test -s "$KOUT/vmlinux"
test -s "$KOUT/System.map"
test -s "$KOUT/compile_commands.json"

printf 'kernel analysis input is ready:\n'
printf '  config: %s\n' "$KOUT/.config"
printf '  compile database: %s\n' "$KOUT/compile_commands.json"
