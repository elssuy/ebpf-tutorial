# eBPF - Tutorial project

This repository contains examples that you can use to understand and write ebpf programs using `cilium/ebpf`.
All project are found in `cmd/` folder. For each one you can run:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h # Generate vmlinux header for your kernel version
go generate # Generate eBPF binaries
go run -exec sudo . # Run the eBPF program
```

# 1 - Hello world [Tracepoint]

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

# Tips

## Availables Tracepoints

Tracepoints can be found in `/sys/kernel/debug/tracing/events/*`.
For example to trace `execve` calls see: `/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format`

## Available symboles

For kProbes, symboles can be found here: `/proc/kallsyms`.

