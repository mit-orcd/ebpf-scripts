/**
 * to generate "vmlinux.h" run
 *      `bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h`
 *
 *  to generate "nfsd-btf.h" run
 *      `bpftool btf dump file /sys/kernel/btf/nfsd format c > bpf/nfsd-btf.h`
 *
 * then utilize ebpf-go to build
 *      `go generate && go build`
 **/

#include "nfsd-btf.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct key_t {
    __u64 ino;
    __u32 uid;
    __u32 ipv4;
};

// Values of interest (for reference):
// uid: rqstp->rq_cred.cr_uid.val
// ip: rqstp->rq_addr
// inode: cstate->current_fh.fh_dentry->d_inode->i_ino;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct key_t);
    __type(value, __u64);
    __uint(max_entries, 10240); // 10240 * (8+4+4 + 8) = 10240 * 24 = ~0.25 MB
} nfs_ops_counts SEC(".maps");

SEC("fentry/nfsd4_write")
int write_ops(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
              union nfsd4_op_u *u) {
    struct key_t key = {};

    // read inode number
    struct dentry *dentry_ptr = BPF_CORE_READ(cstate, current_fh.fh_dentry);
    struct inode *inode_ptr = BPF_CORE_READ(dentry_ptr, d_inode);

    if (!dentry_ptr || !inode_ptr) {
        // bpf_printk("Could not read inode!\n");
        return 0;
    }

    key.ino = BPF_CORE_READ(inode_ptr, i_ino);

    // read uid
    key.uid = BPF_CORE_READ(rqstp, rq_cred.cr_uid.val);

    __u64 *count = bpf_map_lookup_elem(&nfs_ops_counts, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
        // Note: may instead add bytes written
        //! u->write.wr_bytes_written
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&nfs_ops_counts, &key, &init, BPF_ANY);
    }

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";