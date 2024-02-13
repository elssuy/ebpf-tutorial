//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "GPL";

/*
 *  cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
 *  name: sys_enter_execve
 *  ID: 773
 *  format:
 *  	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
 *  	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
 *  	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
 *  	field:int common_pid;	offset:4;	size:4;	signed:1;
 *
 *  	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *  	field:const char * filename;	offset:16;	size:8;	signed:0;
 *  	field:const char *const * argv;	offset:24;	size:8;	signed:0;
 *  	field:const char *const * envp;	offset:32;	size:8;	signed:0;
 *
 *  print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))
 *
 */

// trace_entry: padding of 8 Bytes (https://en.cppreference.com/w/c/language/arithmetic_types)
SEC("tracepoint/syscalls/sys_enter_execve")
int BPF_PROG(ListExecve, struct trace_entry *te, int syscall_nr, const char *filename, const char *const *argv)
{

  bpf_printk("execve(%d) called with filename: %s", syscall_nr, filename);

  for (int i = 0; i < sizeof(argv); i++)
  {
    const char *str;
    bpf_core_read_user_str(&str, sizeof(str), &argv[i]);
    if (!str)
    {
      break;
    }

    bpf_printk("(%p) argv[%d]: %s", str, i, str);
  }

  return 0;
}

// Working struct
// struct syscall_enter_execve {
//	short unsigned int type;
//	unsigned char flags;
//	unsigned char preempt_count;
//	int pid;
//
//
//	long int id;
//  const char* filename;
//  const char* const* argv;
//  const char* const* envp;
//};

// Working signature:
// int sys_enter_execve(struct trace_event_raw_sys_enter* ctx) {

// struct syscall_enter_execve {
//   unsigned short common_type;
//   unsigned char common_flags;
//   unsigned char common_preempt_count;
//   int common_pid;
// 
//   int __syscall_nr;
//   const char* filename;
//   const char* const* argv;
//   const char* const* envp;
// };
// 
// SEC("tracepoint/syscalls/sys_enter_execve")
// int ListExecve(struct syscall_enter_execve* ctx) {
// 
//   const char* p;
//   bpf_core_read(&p, sizeof(p), &ctx->argv);
//   bpf_printk("[direct] execve(%d) called with argv: %s", ctx->__syscall_nr, p);
// //  bpf_printk("[func  ] execve(%d) called with arg: %s", ctx->__syscall_nr, str);
// 
// 
//   return 0;
// }
// 
