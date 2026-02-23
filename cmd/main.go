package main

import (
	"os"
	"lucy/cmd/dump"
	"lucy/cmd/iface"
	"lucy/cmd/monitor"
	"lucy/cmd/ping"
	"lucy/cmd/run"
	"lucy/cmd/secret"
	"lucy/cmd/version"
	"lucy/cmd/wizard"
	"lucy/internal/flog"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "lucy",
	Short: "KCP transport over raw TCP packet.",
	Long:  `lucy is a bidirectional packet-level proxy using KCP and raw socket transport with encryption.`,
}

func main() {
	rootCmd.AddCommand(run.Cmd)
	rootCmd.AddCommand(dump.Cmd)
	rootCmd.AddCommand(ping.Cmd)
	rootCmd.AddCommand(secret.Cmd)
	rootCmd.AddCommand(iface.Cmd)
	rootCmd.AddCommand(version.Cmd)
	rootCmd.AddCommand(wizard.Cmd)
	rootCmd.AddCommand(monitor.Cmd)

	if err := rootCmd.Execute(); err != nil {
		flog.Errorf("%v", err)
		os.Exit(1)
	}
}
