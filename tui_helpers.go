package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os/user"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
)

// func makeColumns(width int) []table.Column {
// 	return []table.Column{
// 		{Title: "USER", Width: width * 5 / 100},
// 		{Title: "PATH", Width: width * 15 / 100},
// 		{Title: "READS", Width: width * 5 / 100},
// 		{Title: "RBYTES", Width: width * 5 / 100},
// 		{Title: "WRITES", Width: width * 5 / 100},
// 		{Title: "WBYTES", Width: width * 5 / 100},
// 	}
// }

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

func (m *model) updateUserTable() {
	// 1. get users and their metrics from data_window
	// 2. display it

	// m.sw.total_summary.users

}

func (m *model) updateTrafficTableWithIP(uid uint32) {

}

func (m *model) updateTables() tea.Msg {

	m.user_table.SetColumns(makeUserColumns(m.width))
	m.user_table.SetHeight(m.height - 4) // subtract space for header/footer/borders

	m.traffic_table.SetColumns(makeTrafficColumnsWithIP(m.width))
	m.traffic_table.SetHeight(m.height - 4) // subtract space for header/footer/borders

	rows_users := make([]table.Row, 0)
	rows_traffic := make([]table.Row, 0)

	for usr, umetrics := range m.sw.total_summary.users {

		// uid to username resolution
		var username string
		usrstr := fmt.Sprintf("%d", usr)
		u, err := user.LookupId(usrstr)
		if err != nil {
			// fall back to uid
			username = usrstr
		} else {
			username = u.Username
		}

		for ino_ip, metrics := range umetrics.files {

			// ino to filename resolution
			filename, ok := m.sw.ino_to_filenames[ino_ip.ino]
			if !ok {
				// fall back to ino
				filename = fmt.Sprintf("%d", ino_ip.ino)
			}

			r_user := table.Row{
				username,
				"",
				"",
			}
			rows_users = append(rows_users, r_user)

			r_traffic := table.Row{
				filename,
				parse_ip(ino_ip.ip),
				fmt.Sprintf("%d", metrics.r_ops_count),
				fmt.Sprintf("%d", metrics.r_bytes),
				fmt.Sprintf("%d", metrics.w_ops_count),
				fmt.Sprintf("%d", metrics.w_bytes),
				filename,
			}
			rows_traffic = append(rows_traffic, r_traffic)
		}
	}

	m.user_table.SetRows(rows_users)
	m.traffic_table.SetRows(rows_traffic)

	return nil
}
