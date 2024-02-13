//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "GPL";

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dirfd, struct filename* name) 
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
  const char* fname = BPF_CORE_READ(name, name);

	bpf_printk("KPROBE ENTRY pid = %d, filename = %s", pid, fname);

	return 0;
}

