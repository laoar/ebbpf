#!/bin/bash

BPFTOOL="/bin/bpftool"
LIBBPF_PATH="/data0/yafang/bpf-next/tools/lib/bpf/"

name="fentry"

$BPFTOOL btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I . -c ${name}.bpf.c -o ${name}.bpf.o
$BPFTOOL gen skeleton  ${name}.bpf.o > ${name}.skel.h 
clang -Wall -Wno-unused-function -g -O2 -I .  -c ${name}.c -o ${name}.o

# static
clang  -g -O2 -no-pie ${name}.o ${LIBBPF_PATH}/libbpf.a -lelf -lz -o ${name} 
#strip ${name}

