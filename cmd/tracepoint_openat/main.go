//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event bpf openat.c -- -I.

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
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
	kp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.SysEnterOpenat, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Setup ringbuffer
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuffer reader: %s", err)
	}
	defer rd.Close()

	// Setup ring buffer reader close
	go func() {
		<-stop

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuffer reader: %s", err)
		}
	}()

	// Logic

	log.Printf("Run: sudo cat /sys/kernel/debug/tracing/trace_pipe")

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting...")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuffer event: %s", err)
			continue
		}

		name := ToString(event.Name[:])
		comm := ToString(event.Comm[:])

		log.Printf("filename: %s\t comm:%s\n", name, comm)
	}

	// whait ...
	// ticker := time.NewTicker(1 * time.Second)
	// for range ticker.C {
	// 	log.Printf(".")
	// }

}

func ToString(in []int8) string {
	var out []byte = make([]byte, len(in))
	for _, b := range in {
		out = append(out, byte(b))
	}
	return string(out)
}
