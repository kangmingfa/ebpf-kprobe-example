CLANG ?= clang

default: deps
	# bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	${CLANG}  -g -O2 -I .  -target bpf -D__TARGET_ARCH_x86 -c kprobe.bpf.c -o kprobe.bpf.o
	bpftool gen skeleton kprobe.bpf.o > kprobe.skel.h
	gcc kprobe.c -lbpf -o kprobe
deps:
	@bpftool version > /dev/null
	@ls /sys/kernel/btf/vmlinux > /dev/null

clean:
	rm vmlinux.h kprobe.bpf.o kprobe.skel.h kprobe

.PHONY: default clean deps