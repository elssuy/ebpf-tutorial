//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf execve.c -- -I.

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {

	// channels
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load program
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Link program to probs or tracepoint
	kp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.ListExecve, nil)
	//kp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.SysEnterExecve, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %s", err)
	}
	defer kp.Close()

  log.Println("Run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see logs")

  <-stop

}
