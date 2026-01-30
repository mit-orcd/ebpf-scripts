package main

import (
	"encoding/binary"
	"net/netip"

	"github.com/charmbracelet/bubbles/table"
)

func makeColumns(width int) []table.Column {
	return []table.Column{
		{Title: "USER", Width: width * 5 / 100},
		{Title: "PATH", Width: width * 15 / 100},
		{Title: "READS", Width: width * 5 / 100},
		{Title: "RBYTES", Width: width * 5 / 100},
		{Title: "WRITES", Width: width * 5 / 100},
		{Title: "WBYTES", Width: width * 5 / 100},
	}
}

func makeUserColumns(width int) []table.Column {
	return []table.Column{
		{Title: "USER", Width: width * 12 / 100},
		{Title: "I/O (kB)", Width: width * 8 / 100},
		{Title: "%", Width: width * 5 / 100},
	}
}

func makeTrafficColumnsWithIP(width int) []table.Column {
	return []table.Column{
		{Title: "FILENAME", Width: width * 14 / 100},
		{Title: "IPv4", Width: width * 9 / 100},
		{Title: "READS", Width: width * 6 / 100},
		{Title: "RBYTES", Width: width * 9 / 100},
		{Title: "WRITES", Width: width * 6 / 100},
		{Title: "WBYTES", Width: width * 9 / 100},
		{Title: "PATH", Width: width * 30 / 100},
	}
}

func parse_ip(ip uint32) string {
	var ipBytes [4]byte
	binary.LittleEndian.PutUint32(ipBytes[:], ip)
	ip_addr := netip.AddrFrom4(ipBytes)
	return ip_addr.String()
}
