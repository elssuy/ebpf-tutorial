//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "GPL";

_Bool LINUX_HAS_SYSCALL_WRAPPER = 1;

// See https://www.youtube.com/watch?v=fX1Cv7yToA8
SEC("kprobe/sys_execve")
int BPF_KSYSCALL(sys_execve, const char* filename, const char** argv, const char** envp)
{
  bpf_printk("Execve filename: %s", filename);
  return 0;
}
