package main

import (
	"fmt"
	"os"
	"os/user"
	"time"

	"golang.org/x/term"

	"github.com/charmbracelet/bubbles/help"
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
	user_table    table.Model
	traffic_table table.Model
	sw            *SlidingWindow
	objs          *collectorObjects
	width         int
	height        int
	help          help.Model
}

type updateTickMsg time.Time

func updateTableEvery(delay time.Duration) tea.Cmd {
	return tea.Every(delay, func(t time.Time) tea.Msg {
		return updateTickMsg(t)
	})
}

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

func updateTable(m *model) tea.Msg {

	m.user_table.SetColumns(makeColumns(m.width))
	m.user_table.SetHeight(m.height - 4) // subtract space for header/footer/borders

	m.traffic_table.SetColumns(makeColumns(m.width))
	m.traffic_table.SetHeight(m.height - 4) // subtract space for header/footer/borders

	m.sw.total_summary.UpdateTotalWindow(m.objs.NfsOpsCounts)

	rows := make([]table.Row, 0)

	for usr, files := range m.sw.total_summary.m {

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

		for ino, metrics := range files.files {

			// ino to filename resolution
			filename, ok := m.sw.ino_to_filenames[ino]
			if !ok {
				// fall back to ino
				filename = fmt.Sprintf("%d", ino)
			}

			r := table.Row{
				username,
				filename,
				fmt.Sprintf("%d", metrics.r_ops_count),
				fmt.Sprintf("%d", metrics.r_bytes),
				fmt.Sprintf("%d", metrics.w_ops_count),
				fmt.Sprintf("%d", metrics.w_bytes),
			}
			rows = append(rows, r)
		}
	}

	m.user_table.SetRows(rows)

	return nil
}

func (m *model) Init() tea.Cmd { return updateTableEvery(1 * time.Second) }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case updateTickMsg:
		updateTable(m)
		return m, tea.Batch(
			updateTableEvery(1 * time.Second),
		)
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			// this toggles wether table can receive user input
			if m.user_table.Focused() {
				m.user_table.Blur()
			} else {
				m.user_table.Focus()
			}
		case "q", "ctrl+c":
			return m, tea.Quit
		case "enter":
			return m, tea.Batch(
				tea.Printf("Let's go to %s!", m.user_table.SelectedRow()[1]),
			)
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		updateTable(m)
	}

	m.user_table, cmd = m.user_table.Update(msg) // table keymaps
	return m, cmd
}

func (m *model) View() string {
	left := baseStyle.Render(m.user_table.View())
	right := baseStyle.Render(m.traffic_table.View())
	joint := lipgloss.JoinHorizontal(lipgloss.Top, left, right)

	helpView := m.help.ShortHelpView(m.user_table.KeyMap.ShortHelp())
	return joint + "\n" + helpView + "\n"
}

func render(sw *SlidingWindow, objs *collectorObjects) {

	w, h, err := term.GetSize(0)
	if err != nil {
		fmt.Println("Could not get window size, making best guess")
		w, h = 80, 25
	}

	columns := makeColumns(w)

	rows := []table.Row{
		{"1", "test", "1", "4096", "31", "51283491"},
	}

	users_table := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(h-5), // padding
	)

	traffic_table := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(false),
		table.WithHeight(h-5),
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
	users_table.SetStyles(s)
	traffic_table.SetStyles(s)

	m := model{users_table, traffic_table, sw, objs, w, h, help.New()}
	if _, err := tea.NewProgram(&m, tea.WithAltScreen()).Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
