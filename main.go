package main

import (
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
)

const atomic = true

const time_per_query = 1

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

	ticker := time.NewTicker(time_per_query * time.Second)
	defer ticker.Stop()

	// to do: every x seconds - gets all map data (flushes map), adds it to sliding window
	for {
		select {
			case <-kill_sig:
				log.Printf("Exiting...")
				return

			case <-ticker.C:
				
				iterator := objs.collectorMaps.NfsOpsCounts.Iterate()
				

				if atomic { /* atomic == true */
					// obtains exact amount of data
					// first takes a snapshot of current keys
					// then for each key gathers the values and deletes it from the map
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

						log.Printf("UID: %d | Inode: %d | Requests: %d | Total Bytes: %d\n", k.Uid, k.Ino, val.Requests, val.Bytes)
					}
				} else { /* atomic == false */
					// much higher throughput, but may lose some data due to race condition
					// var key collectorKeyT
					// var val uint64
					// for iterator.Next(&key, &val) {
					// 	log.Printf("UID: %d | Inode: %d | Count: %d\n", key.Uid, key.Ino, val)
					// 	// delete immediately, is this safe?
					// 	if err := objs.collectorMaps.NfsOpsCounts.Delete(key); err != nil {
					// 		log.Printf("Delete error %v", err) 
					// 	}
						
					// }

					// todo: make something like this work (much faster but slightly less reliable)
					// const batchSize = 256
					// cursor := &ebpf.MapBatchCursor{}
                    // for {
                    //     keys := make([]collectorKeyT, batchSize)
                    //     vals := make([]uint64, batchSize)
                    //     n, err := objs.collectorMaps.NfsOpsCounts.BatchLookupAndDelete(cursor, keys, vals, nil)
					// 	log.Printf("%d", n)
                    //     if err != nil {
                    //         // treat empty map / no more entries as done
                    //         if err == ebpf.ErrKeyNotExist || n == 0 {
                    //             break
                    //         }
                    //         log.Printf("Batch error: %v", err)
                    //         break
                    //     }

                    //     for i := 0; i < n; i++ {
                    //         k := keys[i]
                    //         v := vals[i]
                    //         log.Printf("UID: %d | Inode: %d | Count: %d\n", k.Uid, k.Ino, v)
                    //     }

                    //     if n < batchSize {
                    //         // drained the map
                    //         break
                    //     }
                    // }

				}
		
		}		
	}
}