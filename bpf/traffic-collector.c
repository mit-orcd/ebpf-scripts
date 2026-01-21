/**
 * to generate "vmlinux.h" run
 *   `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
 *
 * then utilize ebpf-go to build
 *   `go generate && go build`
 **/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
// #include <bpf/bpf_core_read.h>

// #include <linux/bpf.h> // gives conflicts with vmlinux.h

struct {
    __uint(type,
           BPF_MAP_TYPE_ARRAY); // todo see what are all the other types of maps
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps");

// count_packets atomically increases a packet counter on every invocation.
SEC("fentry/nfsd4_write")
int write_ops(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
              union nfsd4_op_u *u) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    // prints to /sys/kernel/debug/tracing/trace_pipe
    // bpf_printk("nfsd4_write! %i\n", *count);
    // TODO check why bpf_printk gives error
    // Loading eBPF objects:field WriteOps: program write_ops: load program:
    // permission denied: 10: (79) r3 = *(u64 *)(r0 +0): R0 invalid mem access
    // 'scalar' (15 line(s) omitted)

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";