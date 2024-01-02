//go:build ignore


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

SEC("tp/syscalls/sys_enter_execve")
int helloworld() {
  bpf_printk("hello world");
  return 0;
}
