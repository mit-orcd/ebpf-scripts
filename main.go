package main

import (
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
)

// run `go generate && go build` and then ./nfs-traffic-viewer

func main() {

	kill_sig := make(chan os.Signal, 1)
	signal.Notify(kill_sig, os.Interrupt) // catch exiting program

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

	log.Printf("Program Loaded!\n")

	ticker := time.NewTicker(5 * time.Second) // tries to do exactly every 5 seconds, regardless of execution time
	defer ticker.Stop()

	// every x seconds - gets all map data (flushes map), adds it to sliding window
	for range ticker.C {

		select {
			case <-ticker.C:
				var key collectorKeyT
				var	val uint64
				
				iterator := objs.collectorMaps.NfsOpsCounts.Iterate()

				for iterator.Next(&key, &val) {
					log.Printf("UID: %d | Inode: %d | Count: %d\n", key.Uid, key.Ino, val)
				}

			case <-kill_sig:
				<-kill_sig
				log.Printf("Exiting...")
		
		}		
	}
}