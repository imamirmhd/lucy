package monitor

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var showConnections bool

func init() {
	Cmd.Flags().BoolVarP(&showConnections, "connections", "c", false, "Show network connection traffic (iftop).")
}

var Cmd = &cobra.Command{
	Use:   "monitor",
	Short: "Global system monitor — glances or connection traffic.",
	Long: `The 'monitor' command launches a system-wide monitor.

By default it opens glances for a full system overview.
Use --connections (-c) to show live network traffic via iftop.`,
	Run: func(cmd *cobra.Command, args []string) {
		if showConnections {
			runConnections()
			return
		}
		runGlances()
	},
}

func runGlances() {
	bin, err := exec.LookPath("glances")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: glances not found in PATH.")
		fmt.Fprintln(os.Stderr, "Install: pip install glances  |  apt install glances")
		os.Exit(1)
	}

	proc := exec.Command(bin)
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	proc.Env = append(os.Environ(), "LANG=C.UTF-8", "LC_ALL=C.UTF-8")
	if err := proc.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Monitor exited: %v\n", err)
		os.Exit(1)
	}
}

func runConnections() {
	bin, err := exec.LookPath("iftop")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: iftop not found in PATH.")
		fmt.Fprintln(os.Stderr, "Install: apt install iftop  |  yum install iftop")
		os.Exit(1)
	}

	proc := exec.Command(bin)
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	proc.Env = append(os.Environ(), "LANG=C.UTF-8", "LC_ALL=C.UTF-8")
	if err := proc.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Connection monitor exited: %v\n", err)
		os.Exit(1)
	}
}
