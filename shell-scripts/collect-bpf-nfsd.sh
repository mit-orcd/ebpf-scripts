#!/bin/bash

format='telegraf'
bpfscript='/usr/local/sbin/bpf-nfsd.bt'

# only used for graphite
graphiteify() {
	echo $1 | tr '.' '_'
}
gtmpfile='/tmp/graphite-nfsclients'
gprefix="nfs.$(graphiteify $(hostname -f)).clients"

HELP="Usage: collect-bpf-nfsd.sh [OPTIONS]

Optional:
    -f|--format FORMAT
        Output format (default: $format)
	Supported formats: telegraf, graphite
    --bpf-script PATH
        Location of the BPF script (default: $bpfscript)
    --graphite-prefix PREFIX
        Metric prefix for graphite output (default: $gprefix)
    --graphite-tmpfile PATH
        Temp file for graphite output (default: $gtmpfile)
    -h|--help
        Print this help message and exit
"

to_ipv4() {
	local num=$1
	local x1=$((num%256))
	num=$((num/256))
	local x2=$((num%256))
	num=$((num/256))
	local x3=$((num%256))
	num=$((num/256))
	local x4=$((num%256))

	echo "$x1.$x2.$x3.$x4"
}

telegraf() {
	echo "count,uid,ip"
	# bpftrace -q - < "$bpfscript" | grep -v "Lost" | sed '/^$/d' | awk '{print $3, $4}' | sort | uniq -c | awk '{print $1","$2","$3}'

	# todo - see how to deal with lost packages
	bpftrace -q - < "$bpfscript" | sed '/^$/d' | awk -F'[\\[,\\]: ]' '{print $7","$4","$2}' | \
	while IFS=, read -r count ip uid; do
        echo "${count},${uid},$(to_ipv4 "$ip")"
    done

	# TODO check type to decide if ipv4 or ipv6
}

graphite() {
	timestamp=$(date +%s)

	bpftrace -q - < "$bpfscript" | grep -v "Lost" | sed '/^$/d' | awk '{print $2, $3, $4}' | sort | uniq -c > "$gtmpfile"

	# try to resolve ip addresses
	for ipaddr in $(awk '{print $4}' "$gtmpfile" | sort | uniq); do
		host=$(graphiteify $(dig +short -x $ipaddr | sed 's/\.$//'))
		if [ "$host" != "" ]; then
			sed -i "s/ ${ipaddr}$/ ${host}/g" "$gtmpfile"
		else
			ip_under=$(graphiteify $ipaddr)
			sed -i "s/ ${ipaddr}$/ ${ip_under}/g" "$gtmpfile"
		fi
	done

	# try to resole uids
	for uid in $(awk '{print $3}' "$gtmpfile" | sort | uniq); do
		uname=$(awk -F':' '{print $1, $3}' /etc/passwd | grep -w "$uid" | awk '{print $1}')
		if [ "$uname" != "" ]; then
			sed -i "s/ ${uid} / ${uname} /g" "$gtmpfile"
		fi
	done

	while read -r num opcode uid ipaddr; do
		echo "${gprefix}.by-opcode.${opcode}.${uid}.${ipaddr} $num $timestamp"
		echo "${gprefix}.by-client.${ipaddr}.${uid}.${opcode} $num $timestamp"
		echo "${gprefix}.by-user.${uid}.${opcode}.$ipaddr $num $timestamp"
	done < "$gtmpfile"

	rm -f "$gtmpfile"
}

while [[ "$#" -gt 0 ]]; do
	case $1 in
		-h|--help)
			echo "$HELP"
			exit 0
			;;
		-f|--format)
			format=$2
			shift; shift
			;;
		--bpf-script)
			bpfscript=$2
			shift; shift
			;;
		--graphite-prefix)
			gprefix=$2
			shift; shift
			;;
		--graphite-tmpfile)
			gtmpfile=$2
			shift; shift
			;;
		*)
			echo "Unrecognized option $1"
			echo "$HELP"
			exit 1
			;;
	esac
done

if [ ! -f "$bpfscript" ]; then
	echo "BPF script $bpfscript does not exist"
	exit 1
fi

case $format in
	telegraf)
		telegraf
		;;
	graphite)
		graphite
		;;
	*)
		echo "Unknown format $format"
		exit 1
		;;
esac
