#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry")
int fentry_run(struct pt_regs *ctx)
{
	bpf_printk("fentry\n");
	return 0;
}

