# eBPF Scripts for HPC

This is (the start of) a collection of useful eBPF scripts for instrumenting HPCs 

## Installing eBPF tools

You will need to install `bpftrace` and the appropriate Kernel headers on your system. On Red Hat-likes:

```
dnf install bpftrace kernel-headers-$(uname -r)
```

## Design of the scripts
These scripts are intended to produce output that can be easily scraped by shell tools and forwarded to central collector systems (such as Telegraf). 

## Running the scripts
You can either run the scripts as standalone scripts (i.e., `./nfsd.bt`) or invoke the `bpftrace` tool (e.g. `bpftrace nfsd.bt`). 

These sample the various tracepoints for a short interval, such that they can be executed on a cron or another similar tool. 
