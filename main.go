package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
)

// run `go generate && go build` and then ./nfs-traffic-viewer

func main() {

	// Load eBPF objects to the objs struct (not the kernel yet!)
	var objs collectorObjects
	if err := loadCollectorObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Attach to kernel (e.g. PERF_EVENT_IOC_SET_BPF syscall)
	// https://pkg.go.dev/github.com/cilium/ebpf/link#Kprobe
	// https://pkg.go.dev/github.com/cilium/ebpf/link#AttachTracing
	// https://github.com/cilium/ebpf/blob/main/examples/fentry/main.go
	link, err := link.AttachTracing(link.TracingOptions{
		Program: objs.WriteOps,
	})
	if err != nil {
		log.Fatal("Attaching Fentry:", err)
	}
	defer link.Close()

	log.Printf("Program Loaded!")

	var key uint32 = 0
	var count uint64

	for {
		if err := objs.PktCount.Lookup(&key, &count); err != nil {
			log.Fatal("map lookup:", err)
		}
		log.Printf("count=%d", count)

		if count >= 100 {
			break
		}
		time.Sleep(500*time.Millisecond)
	}
}