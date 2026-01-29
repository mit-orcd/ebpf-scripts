package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
)

func main() {

	/* Load and Attach eBPF Programs */

	kill_sig := make(chan os.Signal, 1)
	signal.Notify(kill_sig, os.Interrupt) // catch exiting program

	// Load eBPF objects to the objs struct
	var objs collectorObjects
	if err := loadCollectorObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Attach to kernel
	wlink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.WriteOps,
	})
	if err != nil {
		log.Fatal("Attaching Write Fentry:", err)
	}
	defer wlink.Close()

	rlink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.ReadOps,
	})
	if err != nil {
		log.Fatal("Attaching Read Fentry:", err)
	}
	defer rlink.Close()

	log.Printf("Programs Loaded!\n")

	/* Window & Display Logic */
	sw := InitWindow()

	go sw.MaintainInodeResolution(objs.collectorMaps.Events)

	render(&sw, &objs)

	// ticker := time.NewTicker(time_per_query * time.Second)
	// defer ticker.Stop()
	// for {
	// 	select {
	// 	case <-kill_sig:
	// 		log.Printf("Exiting...")
	// 		return

	// 	case <-ticker.C:

	// 		/* TODO: Change for bubble tea TUI */
	// 		fmt.Print("\033[H\033[2J")
	// 		log.Printf("Accumulated Writes:")

	// 		for usr, files := range sw.total_summary.m {
	// 			fmt.Printf("===== UID %d =====\n", usr)
	// 			for ino, metrics := range files.files {
	// 				fmt.Printf("ino %d: r%d rb%d w%d wb%d\n", ino, metrics.r_ops_count, metrics.r_bytes, metrics.w_ops_count, metrics.w_bytes)
	// 			}
	// 		}

	// 		fmt.Printf("\n\n==== LOG ====\n")

	// 		sw.total_summary.UpdateTotalWindow(objs.NfsOpsCounts)

	// To do:
	// 1. Switch running map
	// 2. Create window for current map
	// 3. Update sliding window
	// 	}
	// }
}
