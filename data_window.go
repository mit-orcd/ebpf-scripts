package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
)

type SlidingWindow struct {
	time_per_update_ms   int
	total_display_time_s int

	windows              []WindowSummary
	start_window         int // index of oldest window
	current_window       int // index of newest window
	windows_max_quantity int // maximum number of windows to store

	total_summary WindowSummary
}

type WindowSummary struct {
	// m map[collectorKeyT]collectorValT
	m map[uint32]UserMetrics // user --> UserMetrics
}

type UserMetrics struct {
	files map[uint64]FileMetrics // ino --> Filemetrics
}

type FileMetrics struct {
	r_ops_count uint64
	r_bytes     uint64
	w_ops_count uint64
	w_bytes     uint64
}

func InitWindow() SlidingWindow {
	sw := SlidingWindow{}
	sw.total_summary.m = make(map[uint32]UserMetrics)

	return sw
}

func (w WindowSummary) UpdateTotalWindow(ebpf_map *ebpf.Map) {
	iterator := ebpf_map.Iterate()

	// todo: implement two-buffer collections system
	var keys []collectorKeyT

	var valtmp collectorValT
	var key collectorKeyT
	// populate all the keys
	for iterator.Next(&key, &valtmp) {
		keys = append(keys, key)
	}

	// obtain the values corresponding to the keys
	for _, k := range keys {
		var val collectorValT
		if err := ebpf_map.LookupAndDelete(k, &val); err != nil {
			log.Printf("Delete error %v", err)
			continue
		}

		fmt.Printf("UID: %d | Inode: %d | Requests: %d | Total Bytes: %d\n", k.Uid, k.Ino, val.W_requests, val.W_bytes)

		um, ok := w.m[k.Uid]
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
		fm.w_ops_count += val.W_requests
		fm.w_bytes += val.W_bytes
		fm.r_ops_count += val.R_requests
		fm.r_bytes += val.R_bytes

		um.files[k.Ino] = fm
		w.m[k.Uid] = um
	}
}
