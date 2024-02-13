# eBPF - Tutorial project

## Run localy
To run example please install required packages:
- libbpf-dev
- bpftool
- clang
- llvm

This repository contains examples that you can use to understand and write ebpf programs using `cilium/ebpf`.
All project are found in `cmd/` folder. You can inspect the makefile to see wich command to execute:
```bash
make generate # Compile all eBPF programs
make build # Compile all example into bin/ folder

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h # Generate vmlinux header for your kernel version
go generate -C cmd/01_helloworld  # Generate eBPF binaries for one example
go run -C cmd/01_helloworld -exec sudo . # Run the eBPF program for on example
```

## Run inside container

To run examples inside docker container:
```bash
make docker
make run
$ ./bin/01_helloworld
```
The container mounts `/sys/kernel/tracing/` is mounted in read only and run with CAP_BPF and CAP_SYS_ADMIN. see `man capabilities` for more informations.

Plan:
1) Hello world
2) Tracepoint
3) KProbs
4) How to exchange information with userspace application aka buffertypes

# 1 - [Tracepoint] Hello world 

This eBPF program links to the tracepoint `syscalls/sys_enter_execve`. This syscall is called each time
a program is executed and the kernel enter the syscall. (see `man execve`)

The minimal ebpf program contains:
- `vmlinux.h` include file
- Licence declaration
- The function to call defined in a specific section

`vmlinux.h` can be generated using this command: `bpftool btf dump file /sys/kernel/btf/vmlinux format c` more
on that later

Loading eBPF programs inside linux kernel is similare as loading Linux modules. So the same
licensing rules applies.
Licensing informations inside linux kernel code [here](https://elixir.bootlin.com/linux/v6.6.9/source/include/linux/module.h#L187).
Licensing informations documentation [here](https://docs.kernel.org/process/license-rules.html).
To declare eBPF licence simply defined this variable:
```c
char __license[] SEC("license") = "GPL";
```

Then you have to declare your function at a specific section. Here we are declaring ours in section 
`tp/syscalls/sys_enter_execve`. More information on available sections
[here](https://docs.kernel.org/bpf/libbpf/program_types.html). The section you used will define you eBPF
program type.

```c
#include <bpf/bpf_helpers.h> // header defining bpf_printk function

SEC("tp/syscalls/sys_enter_execve") // The section we are talking about
int helloworld() {
  bpf_printk("hello world\n"); // Print function used inside ebpf programs
  return 0;
}
```

One you've started the program. You can `sudo cat /sys/kernel/debug/tracing/trace_pipe` 
and see the logs output of the eBPF program (to trigger an `execve` call some programs like `echo`)

# 2 - [Tracepoint] Printing execve syscall informations 

When you want to get access to tracepoint arguments you need multiple things:
- Get the signature of the tracapoint function.
- Use `BPF_PROG` macro to declare your function.
- Know how to read variables with provided eBPF macros. (see [CO-RE](#Co-Re)) FIXME:

To get function signature. Simply `cat` the corresponding function from 
`/sys/kernel/debug/tracing/events/syscalls/<function_name>/format`. Here we 
`cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format`.

At this point you get two options. Use the `BPF_PROG` macro to declare your function or not.
As descibed on the [comment](https://elixir.bootlin.com/linux/v6.6.9/source/tools/lib/bpf/bpf_tracing.h#L650) 
it is a *convinience wrapper for generic [...] BPF programs* preventing user *to write
manual casts and work with array elements by index*.

The first choice would be to use the macro for further compatibilities.
```c
SEC("tracepoint/syscalls/sys_enter_execve")
int BPF_PROG(ListExecve, struct trace_entry *te, int syscall_nr, const char* filename) {

  bpf_printk("execve(%d) called with filename: %s", syscall_nr, filename);

  return 0;
}
```

In case you don't use the macro your function declaration should look like:
```c
struct syscall_enter_execve {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;

  int __syscall_nr;
  const char* filename;
  const char* const* argv;
  const char* const* envp;
};

SEC("tp/syscalls/sys_enter_execve")
int sys_enter_execve(struct syscall_enter_execve* ctx) {

  bpf_printk("execve(%d) called with filename: %s", ctx->__syscall_nr, ctx->filename);

  return 0;
}
```

TODO: test with array args
TODO: Watch out for `BPF_PROG2` macro !
TODO: Watch out for `struct syscall_trace_enter` and `struct trace_event_raw_sys_enter`


Tracepoint are stable ABI to hook bpf programmes to.
In this example we are hooking to the `tracepoint/syscalls/sys_enter_execve`.
Tracepoint signature can be found here `/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format`.


# Program 3: Kprobe unlinkat

Kprobe are used to probe any linux symboles. Those symboles cas be found in `/proc/kallsyms`.
In this example we are linking the eBPF progam to `do_unlinkat` [implementation here](https://elixir.bootlin.com/linux/latest/source/fs/namei.c#L4361). It is called when a file is deleted from filesystem see `man unlinkat`.

Information:
In this example we are using the `BPF_KPROBE` macro to define our function. This macro expand the
definition to include a context `struct pt_regs *ctx` containing a pointer to CPU registers. 
And it populate args of your fonction with correct registers depending on your architecture
[doc for x86](http://6.s081.scripts.mit.edu/sp18/x86-64-architecture-guide.html).

Warning: Kprobe are not stable ABI and may break depending on kernel version.
That is why you should use **tracepoint** instead.

```c
int BPF_KPROBE(do_unlinkat, int dirfd, struct filename* name) 
{
    // [...]
}

// Will expand to


int do_unlinkat(struct pt_regs *ctx); 
static inline __attribute__((always_inline)) typeof(do_unlinkat(0)) ____do_unlinkat(struct pt_regs *ctx, int dirfd, struct filename* name); 
typeof(do_unlinkat(0)) do_unlinkat(struct pt_regs *ctx) {
    // [...]
    // rdi 1st argument
    // rsi 2nd argument
    return ____do_unlinkat(ctx, (void *)((ctx)->di), (void *)((ctx)->si));
    // [...]
}

static inline __attribute__((always_inline)) typeof(do_unlinkat(0)) ____do_unlinkat(struct pt_regs *ctx, int dirfd, struct filename* name)
{
    // [...]
 return 0;
}
```

# Pogram 4: KProbe on syscalls

KProbes for syscalls are a little bit tricky. You need to use `BPF_KSYSCALL` macro.
And define the variable: ` _Bool LINUX_HAS_SYSCALL_WRAPPER=1;`.

```c
_Bool LINUX_HAS_SYSCALL_WRAPPER = 1;
int BPF_KSYSCALL(sys_execve, const char* filename, const char** argv, const char** envp)
{ /* [...] */ }

// Expands to 

int sys_execve(struct pt_regs *ctx); 
extern _Bool LINUX_HAS_SYSCALL_WRAPPER __attribute__((section(".kconfig"))); 
static inline __attribute__((always_inline)) typeof(sys_execve(0)) ____sys_execve(struct pt_regs *ctx, const char* filename, const char** argv, const char** envp); 
typeof(sys_execve(0)) sys_execve(struct pt_regs *ctx) { 
    struct pt_regs *regs = LINUX_HAS_SYSCALL_WRAPPER ? (struct pt_regs *)((ctx)->di) : ctx;

    if (LINUX_HAS_SYSCALL_WRAPPER) 
        return ____sys_execve(
            ctx, 
            (void *)({ typeof(((regs))->di) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), (const void *)__builtin_preserve_access_index(&((typeof((((regs)))))((((regs)))))->di)); }); __r; }),
            (void *)({ typeof(((regs))->si) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), (const void *)__builtin_preserve_access_index(&((typeof((((regs)))))((((regs)))))->si)); }); __r; }), 
            (void *)({ typeof(((regs))->dx) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), (const void *)__builtin_preserve_access_index(&((typeof((((regs)))))((((regs)))))->dx)); }); __r; })
        ); 
    else return ____sys_execve(
        ctx, 
        (void *)((regs)->di), 
        (void *)((regs)->si), 
        (void *)((regs)->dx)
    );
```

# Sharing data with userspace

Ring buffer vs Perf Buffer
https://nakryiko.com/posts/bpf-ringbuf/

# Hooking to LSM - Linux Security Modules
https://elixir.bootlin.com/linux/latest/source/Documentation/bpf/prog_lsm.rst
https://docs.kernel.org/bpf/prog_lsm.html

# Co-Re (Compile Once Run Everywhere)

This section relie heavily on [this](https://nakryiko.com/posts/bpf-core-reference-guide/) guide written by Andrii Nakryiko.

# Tips

## Availables Tracepoints

Tracepoints can be found in `/sys/kernel/debug/tracing/events/*`.
For example to trace `execve` calls see: `/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format`

## Available symboles

For kProbes, symboles can be found here: `/proc/kallsyms`.

# links
https://github.com/lizrice/ebpf-beginners

https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/
When using libbpf declare array with structs: 
```C
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");
```
Don't use BCC macro such as `BPF_PERF_OUTPUT(events);`

List of program types for libbpf [here](https://github.com/libbpf/libbpf/blob/787abf721ec8fac1a4a0a7b075acc79a927afed9/src/libbpf.c#L7935-L8075)
