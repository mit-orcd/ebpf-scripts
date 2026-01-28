package main

import (
	"fmt"
	"os"
	"os/user"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

/** If Styles do not display in TMUX:

Go to or create ~/.tmux.conf
and append:

```
set -g default-terminal "tmux-256color"
set -g terminal-overrides 'xterm*:Tc'
```

Then set it as the source file
`tmux source-file ~/.tmux.conf`
**/

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

type model struct {
	table table.Model
	sw    *SlidingWindow
	objs  *collectorObjects
}

type updateTickMsg time.Time

func updateTableEvery(delay time.Duration) tea.Cmd {
	return tea.Every(delay, func(t time.Time) tea.Msg {
		return updateTickMsg(t)
	})
}

func updateTable(m *model) tea.Msg {

	/* TODO: Change for bubble tea TUI */
	// fmt.Print("\033[H\033[2J")
	// log.Printf("Accumulated Writes:")

	// for usr, files := range sw.total_summary.m {
	// 	fmt.Printf("===== UID %d =====\n", usr)
	// 	for ino, metrics := range files.files {
	// 		fmt.Printf("ino %d: r%d rb%d w%d wb%d\n", ino, metrics.r_ops_count, metrics.r_bytes, metrics.w_ops_count, metrics.w_bytes)
	// 	}
	// }

	// fmt.Printf("\n\n==== LOG ====\n")

	m.sw.total_summary.UpdateTotalWindow(m.objs.NfsOpsCounts)

	rows := make([]table.Row, 0)

	for usr, files := range m.sw.total_summary.m {
		var username string
		usrstr := fmt.Sprintf("%d", usr)
		u, err := user.LookupId(usrstr)
		if err != nil {
			// fall back to uid
			username = usrstr
		}
		username = u.Username
		for ino, metrics := range files.files {
			// fmt.Printf("ino %d: r%d rb%d w%d wb%d\n", ino, metrics.r_ops_count, metrics.r_bytes, metrics.w_ops_count, metrics.w_bytes)
			r := table.Row{
				username,
				fmt.Sprintf("%d", ino),
				fmt.Sprintf("%d", metrics.r_ops_count),
				fmt.Sprintf("%d", metrics.r_bytes),
				fmt.Sprintf("%d", metrics.w_ops_count),
				fmt.Sprintf("%d", metrics.w_bytes),
			}
			rows = append(rows, r)
		}
	}

	m.table.SetRows(rows)

	return nil
}

func (m *model) Init() tea.Cmd { return updateTableEvery(1 * time.Second) }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case updateTickMsg:
		updateTable(m)
		return m, tea.Batch(
			updateTableEvery(1*time.Second),
			tea.Printf("1 second passed\n"),
		)
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			if m.table.Focused() {
				m.table.Blur()
			} else {
				m.table.Focus()
			}
		case "q", "ctrl+c":
			return m, tea.Quit
		case "enter":
			return m, tea.Batch(
				tea.Printf("Let's go to %s!", m.table.SelectedRow()[1]),
			)
		}
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m *model) View() string {
	return baseStyle.Render(m.table.View()) + "\n"
}

func render(sw *SlidingWindow, objs *collectorObjects) {
	// columns := []table.Column{
	// 	{Title: "Rank", Width: 4},
	// 	{Title: "City", Width: 10},
	// 	{Title: "Country", Width: 10},
	// 	{Title: "Population", Width: 10},
	// }

	columns := []table.Column{
		{Title: "UID", Width: 5},
		{Title: "INO", Width: 8},
		{Title: "READS", Width: 6},
		{Title: "BYTES", Width: 8},
		{Title: "WRITES", Width: 6},
		{Title: "BYTES", Width: 8},
	}

	rows := []table.Row{
		{"1", "123", "1", "4096", "31", "51283491"},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(7),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	m := model{t, sw, objs}
	if _, err := tea.NewProgram(&m, tea.WithAltScreen()).Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
