#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

if [ "$#" -lt 1 ]; then
	echo "Usage: $0 <repo/image | /path/to/binary>"
	echo "	Statically extract all syscalls from an image or a single binary."
	echo "	Useful to know which syscalls NOT to block."
	exit 0
fi


input="$(realpath $1)"
tmpdir=$(mktemp -d)
curdir="$(pwd)"
cd "$tmpdir" || exit 1

if [ -f "$input" ]; then
	# Single binary — just copy it into the scan directory.
	mkdir rootfs
	cp "$input" rootfs/
	ls -la rootfs/
else
	# Container image — save and extract layers.
	container_manager="podman"
	if ! command -v podman > /dev/null 2>&1; then
		container_manager="docker"
	fi

	if ! "${container_manager}" image inspect "$1" > /dev/null 2>&1; then
		"${container_manager}" pull "$1"
	fi
	"${container_manager}" save -o image.tar "$1"

	mkdir rootfs image_layers
	tar xf image.tar -C image_layers
	for layer in image_layers/*/layer.tar; do
		tar xf "$layer" -C rootfs
	done
fi

for i in $(find rootfs -type f); do
	objdump -d "$i" > "$tmpdir/dis" 2> /dev/null || continue
	[ -s "$tmpdir/dis" ] || continue

	# Pattern A: mov immediate to syscall-relevant register near 'syscall' instruction
	# Catches: Go runtime direct syscalls (futex, clone, exit_group, etc.)
	grep -B10 '	syscall$' "$tmpdir/dis" |
		grep -oP 'mov[a-z]*\s+\$0x\K[0-9a-f]+(?=,%(eax|rax|edi|rdi))' >> "hex"

	# Pattern B: mov immediate to %edi near call to named <syscall> wrapper
	# Catches: C code calling musl/libc syscall() (e.g., crun)
	wrapper=$(grep -oP '^0*\K[0-9a-f]+(?= <syscall>:)' "$tmpdir/dis" | head -1)
	if [ -n "$wrapper" ]; then
		grep -B8 "call.*\\b${wrapper}\\b" "$tmpdir/dis" |
			grep -oP 'mov[a-z]*\s+\$0x\K[0-9a-f]+(?=,%edi)' >> "hex"
	fi

	# Pattern C: call-graph reachability from syscall sites
	# Catches: Go Syscall6/RawSyscall dispatch, and any other indirect paths
	# Builds a call graph, finds functions 1-3 call levels above 'syscall',
	# and extracts immediate values loaded into %eax, %rax, %edi, or (%rsp).
	awk '
	/^[0-9a-f]+ </ {
		match($0, /^[0-9a-f]+/)
		a = substr($0, RSTART, RLENGTH)
		gsub(/^0+/, "", a)
		if (a == "") a = "0"
		cf = a
		inp = 0
		next
	}

	!/^\s+[0-9a-f]+:/ { next }

	{
		s = $0; sub(/^\s+/, "", s); sub(/:.*/, "", s); a = s

		if ($0 ~ /\tint3/) { inp = 1; next }
		if (inp) { cf = a; inp = 0 }
		if (cf == "") cf = a

		if ($0 ~ /\tsyscall\s*$/) sc[cf] = 1

		if ($0 ~ /\t(call|jmp)/) {
			t = $0
			sub(/.*\t(call|jmp)[a-z]*\s+/, "", t)
			sub(/[^0-9a-f].*/, "", t)
			if (t ~ /^[0-9a-f]+$/)
				cl[cf] = cl[cf] " " t
		}

		if ($0 ~ /mov[a-z]*\s+\$0x[0-9a-f]+,(%(eax|rax|edi)|\(%rsp\))/) {
			v = $0
			sub(/.*\$0x/, "", v)
			sub(/,.*/, "", v)
			if (v ~ /^[0-9a-f]+$/)
				im[cf] = im[cf] " " v
		}
	}

	END {
		for (f in sc) l0[f] = 1

		for (f in cl) {
			n = split(cl[f], tgt, " ")
			for (i = 1; i <= n; i++)
				if (tgt[i] in l0) { l1[f] = 1; break }
		}
		for (f in cl) {
			n = split(cl[f], tgt, " ")
			for (i = 1; i <= n; i++)
				if (tgt[i] in l1) { l2[f] = 1; break }
		}
		for (f in cl) {
			n = split(cl[f], tgt, " ")
			for (i = 1; i <= n; i++)
				if (tgt[i] in l2) { l3[f] = 1; break }
		}

		for (f in l1) if (f in im) { n = split(im[f], h, " "); for (i = 1; i <= n; i++) if (h[i]) print h[i] }
		for (f in l2) if (f in im) { n = split(im[f], h, " "); for (i = 1; i <= n; i++) if (h[i]) print h[i] }
		for (f in l3) if (f in im) { n = split(im[f], h, " "); for (i = 1; i <= n; i++) if (h[i]) print h[i] }
	}
	' "dis" >> "hex"
done

sort -u "hex" | while read hex; do
	num=$(printf "%d" "0x$hex" 2> /dev/null) || continue
	[ "$num" -ge 0 ] && [ "$num" -le 500 ] || continue
	ausyscall --exact "$num" 2> /dev/null
done | sort -u > "$curdir"/syscalls.log

cd ..
rm -rf "$tmpdir"
