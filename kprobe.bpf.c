#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/inet_csk_get_port")
int BPF_KPROBE(inet_csk_get_port, struct sock *sk, unsigned short snum)
{
	pid_t pid;
	// const char *filename;

	pid = bpf_get_current_pid_tgid() >> 32;
	// filename = BPF_CORE_READ(name, name);
	bpf_printk("KPROBE ENTRY pid = %d, snum = %d\n", pid, snum);
	return 0;
}

SEC("kretprobe/inet_csk_get_port")
int BPF_KRETPROBE(inet_csk_get_port_exit, int ret)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("KPROBE EXIT: pid = %d, ret = %d\n", pid, ret);
	return 0;
}