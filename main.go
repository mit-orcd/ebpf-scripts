package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
)

const atomic = true
const time_per_query = 1

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

	sw := SlidingWindow{}
	// sw.time_per_update_ms = 1000
	// sw.total_display_time_s = 900 // 900s == 15mins
	sw.total_summary = WindowSummary{}
	sw.total_summary.m = make(map[uint32]UserMetrics)

	ticker := time.NewTicker(time_per_query * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-kill_sig:
			log.Printf("Exiting...")
			return

		case <-ticker.C:

			fmt.Print("\033[H\033[2J")
			log.Printf("Accumulated Writes:")

			for usr, files := range sw.total_summary.m {
				fmt.Printf("===== UID %d =====\n", usr)
				for ino, metrics := range files.files {
					fmt.Printf("ino %d: r%d rb%d w%d wb%d\n", ino, metrics.r_ops_count, metrics.r_bytes, metrics.w_ops_count, metrics.w_bytes)
				}
			}

			fmt.Printf("\n\n==== LOG ====\n")

			// 1. Switch running map
			// 2. Create window for current map
			// 3. Update sliding window
			// 4. 4

			// todo: move logic into SlidingWindow
			iterator := objs.collectorMaps.NfsOpsCounts.Iterate()

			// todo: implement two-buffer collections system
			var keys []collectorKeyT

			var valtmp collectorValT
			var key collectorKeyT
			for iterator.Next(&key, &valtmp) {
				keys = append(keys, key)
			}

			for _, k := range keys {
				var val collectorValT
				if err := objs.collectorMaps.NfsOpsCounts.LookupAndDelete(k, &val); err != nil {
					log.Printf("Delete error %v", err)
					continue
				}

				fmt.Printf("UID: %d | Inode: %d | Requests: %d | Total Bytes: %d\n", k.Uid, k.Ino, val.Requests, val.Bytes)

				um, ok := sw.total_summary.m[k.Uid]
				if !ok {
					log.Print("Created new user")
					um = UserMetrics{
						files: make(map[uint64]FileMetrics),
					}
				}
				if um.files == nil {
					um.files = make(map[uint64]FileMetrics)
				}
				fm, ok := um.files[k.Ino]
				if !ok {
					fm = FileMetrics{}
				}
				fm.w_ops_count += val.Requests
				fm.w_bytes += val.Bytes

				um.files[k.Ino] = fm
				sw.total_summary.m[k.Uid] = um
			}

		}
	}
}
