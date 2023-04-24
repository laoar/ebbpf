#!/bin/bash

bpftool btf dump file /sys/kernel/btf/vmlinux  | grep "FUNC " | awk '{print $3; system("./fentry -s" $3)}'
