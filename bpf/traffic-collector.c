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
#include <bpf/bpf_tracing.h>

struct key_t {
    __u64 ino;
    __u32 uid;
    __u32 ipv4;
};

struct val_t {
    __u64 w_requests;
    __u64 w_bytes;
    __u64 r_requests;
    __u64 r_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct key_t);
    __type(value, struct val_t);
    __uint(max_entries, 10240);
} nfs_ops_counts SEC(".maps");

SEC("fentry/nfsd4_write")
int BPF_PROG(write_ops, struct svc_rqst *rqstp,
             struct nfsd4_compound_state *cstate, union nfsd4_op_u *u) {

    struct key_t key = {};

    // get ino
    struct dentry *dentry_ptr = BPF_CORE_READ(cstate, current_fh.fh_dentry);
    if (!dentry_ptr) {
        bpf_printk("Could not read dentry!\n");
        return 0;
    }

    struct inode *inode_ptr = BPF_CORE_READ(dentry_ptr, d_inode);
    if (!inode_ptr) {
        bpf_printk("Could not read inode!\n");
        return 0;
    }

    key.ino = BPF_CORE_READ(inode_ptr, i_ino);

    // get uid
    key.uid = BPF_CORE_READ(rqstp, rq_cred.cr_uid.val);

    // get bytes
    __u32 bytes = BPF_CORE_READ(u, write.wr_payload.buflen);
    bpf_printk("nfs write %u\n", bytes);

    struct val_t *val = bpf_map_lookup_elem(&nfs_ops_counts, &key);
    if (val) {
        val->w_requests++;
        val->w_bytes += bytes;
    } else {
        struct val_t init = {.w_requests = 1,
                             .w_bytes = (__u64)bytes,
                             .r_requests = 0,
                             .r_bytes = 0};
        bpf_map_update_elem(&nfs_ops_counts, &key, &init, BPF_ANY);
    }

    return 0;
}

SEC("fentry/nfsd4_read")
int BPF_PROG(read_ops, struct svc_rqst *rqstp,
             struct nfsd4_compound_state *cstate, union nfsd4_op_u *u) {

    bpf_printk("READ OPERATION");
    struct key_t key = {};

    // get ino
    struct dentry *dentry_ptr = BPF_CORE_READ(cstate, current_fh.fh_dentry);
    if (!dentry_ptr) {
        bpf_printk("Could not read dentry!\n");
        return 0;
    }

    struct inode *inode_ptr = BPF_CORE_READ(dentry_ptr, d_inode);
    if (!inode_ptr) {
        bpf_printk("Could not read inode!\n");
        return 0;
    }

    key.ino = BPF_CORE_READ(inode_ptr, i_ino);

    // get uid
    key.uid = BPF_CORE_READ(rqstp, rq_cred.cr_uid.val);

    // get bytes
    __u32 bytes = BPF_CORE_READ(u, read.rd_length);
    bpf_printk("nfs read %u\n", bytes);

    struct val_t *val = bpf_map_lookup_elem(&nfs_ops_counts, &key);
    if (val) {
        val->r_requests++;
        val->r_bytes += bytes;
    } else {
        struct val_t init = {.r_requests = 1,
                             .r_bytes = (__u64)bytes,
                             .w_requests = 0,
                             .w_bytes = 0};
        bpf_map_update_elem(&nfs_ops_counts, &key, &init, BPF_ANY);
    }

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";