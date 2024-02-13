//go:build ignore


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "GPL";

// Shared memory
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Struct of event
struct event {
  char name[1024];
  char comm[1024];
};
const struct event *unused __attribute__((unused));

/* 
 * $ sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
 *
 * name: sys_enter_openat
 * ID: 695
 * format:
 * 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
 * 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
 * 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
 * 	field:int common_pid;	offset:4;	size:4;	signed:1;
 * 
 * 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 * 	field:int dfd;	offset:16;	size:8;	signed:0;
 * 	field:const char * filename;	offset:24;	size:8;	signed:0;
 * 	field:int flags;	offset:32;	size:8;	signed:0;
 * 	field:umode_t mode;	offset:40;	size:8;	signed:0;
 * 
 * print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))
*/

struct syscall_enter_openat {
  unsigned long long unused;
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;

  int __syscall_nr;
  int dfd;
  void* filename;
  unsigned int flags;
  umode_t mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int sys_enter_openat(struct syscall_enter_openat* ctx) {

  bpf_printk("open called!");
  // Setup event struct
  struct event *task_info;

  // Reserve Ringbuffer
  task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if(!task_info) { return 0; } // Failed to reserve ringbuffer

  // Get infos
  bpf_get_current_comm(&task_info->comm, sizeof(task_info->comm));  // Name of current executable calling
 
  // Write filename to userspace memory
  bpf_probe_read_user_str(task_info->name, sizeof(task_info->name), ctx->filename);
  // bpf_printk("filename: %s", filename);

  // Send to ring buffer
  bpf_ringbuf_submit(task_info, 0);

  return 0;
}

