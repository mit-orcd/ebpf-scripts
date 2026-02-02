/**
 * to generate "vmlinux.h" run
 *      `bpftool btf dump file /sys/kernel/btf/vmlinux format c >
 * bpf/vmlinux.h`
 *
 *  to generate "nfsd-btf.h" run
 *      `bpftool btf dump file /sys/kernel/btf/nfsd format c > bpf/nfsd-btf.h`
 *
 * then utilize ebpf-go to build
 *      `go generate && go build`
 *
 * Also, remember to have kernel-devel and libbpf-devel headers installed
 *
 **/

#include "nfsd-btf.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/** Helper Functions **/

__u32 get_ipv4(struct svc_rqst *rqstp) {
    unsigned char addrbuf[16] = {};
    if (bpf_probe_read_kernel(&addrbuf, sizeof(addrbuf), &rqstp->rq_addr) ==
        0) { // BPF_CORE_READ doesn't work for rqstp->rq_addr?
        unsigned short family = 0;
        __builtin_memcpy(&family, &addrbuf[0], sizeof(family));
        if (family == 2) { /* AF_INET */
            __u32 ipv4 = 0;
            /* sockaddr_in.sin_addr is at offset 4 */
            __builtin_memcpy(&ipv4, &addrbuf[4], sizeof(ipv4));
            return ipv4;
        } else {
            return 0; // default to 0 if ipv6
        }
    } else {
        return 0; // default to 0 if no ip
    }
}

void get_name(char *buf, __u32 buflen, struct dentry *dentry_ptr) {
    const unsigned char *name_ptr = BPF_CORE_READ(dentry_ptr, d_name.name);
    if (name_ptr)
        bpf_probe_read_str(buf, buflen, (const void *)name_ptr);
}

struct dentry *get_parent_dentry(struct dentry *dentry_ptr) {
    return BPF_CORE_READ(dentry_ptr, d_parent);
}

/** End of Helper Functions */

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

struct event {
    __u64 ino;
    Byte name[64];
    Byte pname[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
    __type(value, struct event);
} events SEC(".maps");

// Currently, every read/write will send the filename to userspace, even if the
// userspace already knows it
// todo: implement a BPF_MAP_TYPE_LRU_HASH and add
// logic so that events are not repeatedly sent to the ringbuf if inode filename
// has been sent recently

SEC("fentry/nfsd4_write")
int BPF_PROG(write_ops, struct svc_rqst *rqstp,
             struct nfsd4_compound_state *cstate, union nfsd4_op_u *u) {

    struct key_t key = {};

    // get dentry
    struct dentry *dentry_ptr = BPF_CORE_READ(cstate, current_fh.fh_dentry);
    if (!dentry_ptr) {
        bpf_printk("Could not read dentry!\n");
        return 0;
    }

    // get ino
    struct inode *inode_ptr = BPF_CORE_READ(dentry_ptr, d_inode);
    if (!inode_ptr) {
        bpf_printk("Could not read inode!\n");
        return 0;
    }
    key.ino = BPF_CORE_READ(inode_ptr, i_ino);

    // get filename
    char fname[64];
    get_name(fname, sizeof(fname), dentry_ptr);

    // get parent name
    struct dentry *pdentry_ptr = get_parent_dentry(dentry_ptr);
    char pname[64];
    get_name(pname, sizeof(pname), pdentry_ptr);

    // we can also get parent's parent, etc.: get_parent_dentry(pdentry_ptr)

    // send filename to ringbuf
    struct event ev = {};
    ev.ino = key.ino;
    __builtin_memcpy(ev.name, fname, sizeof(fname));
    __builtin_memcpy(ev.pname, pname, sizeof(pname));
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);

    // get uid
    key.uid = BPF_CORE_READ(rqstp, rq_cred.cr_uid.val);

    // get ipv4
    key.ipv4 = get_ipv4(rqstp);

    // get bytes
    __u32 bytes = BPF_CORE_READ(u, write.wr_payload.buflen);
    bpf_printk("nfs write %u to %u\n", bytes, key.ino);

    // update map (write metrics)
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

// note: due to cache, reading can become troublesome to test
// you might want to run the following to drop page cache
//      echo 3 > /proc/sys/vm/drop_caches
// https://www.kernel.org/doc/Documentation/sysctl/vm.txt#:~:text=To%20free%20slab%20objects%20and%20pagecache%3A

SEC("fentry/nfsd4_read")
int BPF_PROG(read_ops, struct svc_rqst *rqstp,
             struct nfsd4_compound_state *cstate, union nfsd4_op_u *u) {

    bpf_printk("READ OPERATION");
    struct key_t key = {};

    // get dentry
    struct dentry *dentry_ptr = BPF_CORE_READ(cstate, current_fh.fh_dentry);
    if (!dentry_ptr) {
        bpf_printk("Could not read dentry!\n");
        return 0;
    }

    // get ino
    struct inode *inode_ptr = BPF_CORE_READ(dentry_ptr, d_inode);
    if (!inode_ptr) {
        bpf_printk("Could not read inode!\n");
        return 0;
    }
    key.ino = BPF_CORE_READ(inode_ptr, i_ino);

    // get filename
    char fname[64];
    get_name(fname, sizeof(fname), dentry_ptr);

    // get parent name
    struct dentry *pdentry_ptr = get_parent_dentry(dentry_ptr);
    char pname[64];
    get_name(pname, sizeof(pname), pdentry_ptr);

    // send filename to ringbuf
    struct event ev = {};
    ev.ino = key.ino;
    __builtin_memcpy(ev.name, fname, sizeof(fname));
    __builtin_memcpy(ev.pname, pname, sizeof(pname));
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);

    // get uid
    key.uid = BPF_CORE_READ(rqstp, rq_cred.cr_uid.val);

    // get ipv4
    key.ipv4 = get_ipv4(rqstp);

    // get bytes
    __u32 bytes = BPF_CORE_READ(u, read.rd_length);
    bpf_printk("nfs read %u\n", bytes);

    // update map
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