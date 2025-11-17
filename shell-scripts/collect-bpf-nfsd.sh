#!/bin/bash
echo "count,uid,ip"
sudo bpftrace -q - < /usr/local/sbin/bpf-nfsd.bt | grep -v "Lost" | sed '/^$/d' | awk '{print $3, $4}' | sort | uniq -c | awk '{print $1","$2","$3}'
