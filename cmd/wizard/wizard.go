package wizard

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var outputPath string

func init() {
	Cmd.Flags().StringVarP(&outputPath, "output", "o", "config.yaml", "Output path for the generated configuration file.")
}

var Cmd = &cobra.Command{
	Use:   "wizard",
	Short: "Interactive wizard for generating a lucy configuration file.",
	Long:  `The wizard walks you through creating a lucy configuration file with optimal settings and gives recommendations based on your choices.`,
	Run: func(cmd *cobra.Command, args []string) {
		runWizard()
	},
}

func runWizard() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════╗")
	fmt.Println("║       lucy Configuration Wizard         ║")
	fmt.Println("╚══════════════════════════════════════════╝")
	fmt.Println()

	// Step 1: Role
	role := askChoice(reader, "Select role", []string{"client", "server"}, "client")

	// Step 2: Log level
	logLevel := askChoice(reader, "Log level", []string{"none", "debug", "info", "warn", "error", "fatal"}, "info")

	// Step 3: Network interface
	ifaces := listInterfaces()
	fmt.Println("\n📡 Detected network interfaces:")
	for i, iface := range ifaces {
		addrs := getInterfaceAddrs(iface)
		fmt.Printf("   %d) %s [%s] %s\n", i+1, iface.Name, iface.HardwareAddr, addrs)
	}
	ifaceIdx := askInt(reader, "Select interface number", 1, 1, len(ifaces))
	selectedIface := ifaces[ifaceIdx-1]

	// Step 4: IPv4
	ipv4Addr := askString(reader, "IPv4 address (with port, e.g. 192.168.1.100:0, or empty to skip)", "")
	var ipv4RouterMAC string
	if ipv4Addr != "" {
		ipv4RouterMAC = askString(reader, "IPv4 gateway/router MAC address (e.g. aa:bb:cc:dd:ee:ff)", "")
	}

	// Step 5: IPv6
	ipv6Addr := askString(reader, "IPv6 address (e.g. [2001:db8::1]:0, or empty to skip)", "")
	var ipv6RouterMAC string
	if ipv6Addr != "" {
		ipv6RouterMAC = askString(reader, "IPv6 gateway/router MAC address", "")
	}

	if ipv4Addr == "" && ipv6Addr == "" {
		fmt.Println("⚠  Warning: at least one address (IPv4 or IPv6) is required.")
		ipv4Addr = askString(reader, "IPv4 address (required)", "")
		ipv4RouterMAC = askString(reader, "IPv4 gateway/router MAC", "")
	}

	// Step 6: TCP flags
	localFlag := askString(reader, "TCP local flags (default: PA)", "PA")
	remoteFlag := askString(reader, "TCP remote flags (default: PA)", "PA")

	// Step 7: Transport
	protocol := "kcp"

	var serverAddr string
	var conn int
	if role == "client" {
		serverAddr = askString(reader, "Server address (e.g. 10.0.0.100:9999)", "")
		conn = askInt(reader, "Number of KCP connections (1-256)", 1, 1, 256)
	}

	if role == "server" {
		serverAddr = askString(reader, "Listen address (e.g. 0.0.0.0:9999)", "")
	}

	// Step 8: KCP mode with suggestions
	fmt.Println("\n⚡ KCP Mode Recommendations:")
	fmt.Println("   normal  — Conservative, low CPU usage, higher latency")
	fmt.Println("   fast    — Good balance of speed and CPU (recommended for most)")
	fmt.Println("   fast2   — Aggressive retransmit, lower latency, more CPU")
	fmt.Println("   fast3   — Most aggressive, lowest latency, highest CPU")
	fmt.Println("   manual  — Full control over all KCP parameters")
	kcpMode := askChoice(reader, "KCP mode", []string{"normal", "fast", "fast2", "fast3", "manual"}, "fast")

	// Step 9: Encryption with suggestions
	fmt.Println("\n🔒 Encryption Recommendations:")
	fmt.Println("   aes-128-gcm  — Best security + good performance (recommended)")
	fmt.Println("   aes          — Strong security, moderate CPU")
	fmt.Println("   salsa20      — Fast stream cipher, good for high throughput")
	fmt.Println("   xor          — Minimal overhead, weak security (testing only)")
	fmt.Println("   none/null    — No encryption (not recommended)")
	block := askChoice(reader, "Encryption", []string{"aes", "aes-128", "aes-128-gcm", "aes-192", "salsa20", "blowfish", "twofish", "cast5", "3des", "tea", "xtea", "xor", "sm4", "none", "null"}, "aes-128-gcm")

	var key string
	if block != "none" && block != "null" {
		key = askString(reader, "Encryption key (shared secret)", "")
	}

	// Step 10: SOCKS5 (client only)
	var socksEntries []socksEntry
	if role == "client" {
		if askYesNo(reader, "Configure SOCKS5 proxy?", true) {
			for {
				listen := askString(reader, "SOCKS5 listen address (e.g. 127.0.0.1:1080)", "127.0.0.1:1080")
				username := askString(reader, "SOCKS5 username (empty for none)", "")
				password := ""
				if username != "" {
					password = askString(reader, "SOCKS5 password", "")
				}
				socksEntries = append(socksEntries, socksEntry{listen, username, password})
				if !askYesNo(reader, "Add another SOCKS5 entry?", false) {
					break
				}
			}
		}
	}

	// Step 11: Forward (client only)
	var fwdEntries []forwardEntry
	if role == "client" {
		if askYesNo(reader, "Configure port forwarding?", false) {
			for {
				listen := askString(reader, "Forward listen address (e.g. 127.0.0.1:8080)", "")
				target := askString(reader, "Forward target address (e.g. 127.0.0.1:80)", "")
				fwdProto := askChoice(reader, "Forward protocol", []string{"tcp", "udp"}, "tcp")
				fwdEntries = append(fwdEntries, forwardEntry{listen, target, fwdProto})
				if !askYesNo(reader, "Add another forward entry?", false) {
					break
				}
			}
		}
	}

	// Generate YAML
	yaml := generateYAML(role, logLevel, selectedIface.Name,
		ipv4Addr, ipv4RouterMAC, ipv6Addr, ipv6RouterMAC,
		localFlag, remoteFlag, protocol, serverAddr, conn,
		kcpMode, block, key, socksEntries, fwdEntries)

	if err := os.WriteFile(outputPath, []byte(yaml), 0644); err != nil {
		fmt.Printf("❌ Error writing config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✅ Configuration written to: %s\n", outputPath)

	// Print recommendations
	printRecommendations(role, kcpMode, block, conn)
}

type socksEntry struct {
	listen, username, password string
}

type forwardEntry struct {
	listen, target, protocol string
}

func generateYAML(role, logLevel, ifaceName string,
	ipv4Addr, ipv4RouterMAC, ipv6Addr, ipv6RouterMAC string,
	localFlag, remoteFlag, protocol, serverAddr string, conn int,
	kcpMode, block, key string, socks []socksEntry, fwd []forwardEntry) string {

	var b strings.Builder

	b.WriteString(fmt.Sprintf("role: \"%s\"\n\n", role))
	b.WriteString("log:\n")
	b.WriteString(fmt.Sprintf("  level: \"%s\"\n\n", logLevel))

	// SOCKS5
	if len(socks) > 0 {
		b.WriteString("socks5:\n")
		for _, s := range socks {
			b.WriteString(fmt.Sprintf("  - listen: \"%s\"\n", s.listen))
			if s.username != "" {
				b.WriteString(fmt.Sprintf("    username: \"%s\"\n", s.username))
				b.WriteString(fmt.Sprintf("    password: \"%s\"\n", s.password))
			}
		}
		b.WriteString("\n")
	}

	// Forward
	if len(fwd) > 0 {
		b.WriteString("forward:\n")
		for _, f := range fwd {
			b.WriteString(fmt.Sprintf("  - listen: \"%s\"\n", f.listen))
			b.WriteString(fmt.Sprintf("    target: \"%s\"\n", f.target))
			b.WriteString(fmt.Sprintf("    protocol: \"%s\"\n", f.protocol))
		}
		b.WriteString("\n")
	}

	// Network
	b.WriteString("network:\n")
	b.WriteString(fmt.Sprintf("  interface: \"%s\"\n", ifaceName))

	if ipv4Addr != "" {
		b.WriteString("  ipv4:\n")
		b.WriteString(fmt.Sprintf("    addr: \"%s\"\n", ipv4Addr))
		b.WriteString(fmt.Sprintf("    router_mac: \"%s\"\n", ipv4RouterMAC))
	}
	if ipv6Addr != "" {
		b.WriteString("  ipv6:\n")
		b.WriteString(fmt.Sprintf("    addr: \"%s\"\n", ipv6Addr))
		b.WriteString(fmt.Sprintf("    router_mac: \"%s\"\n", ipv6RouterMAC))
	}

	b.WriteString("  tcp:\n")
	b.WriteString(fmt.Sprintf("    local_flag: [\"%s\"]\n", localFlag))
	b.WriteString(fmt.Sprintf("    remote_flag: [\"%s\"]\n", remoteFlag))
	b.WriteString("\n")

	// Server / Listen
	if role == "server" {
		b.WriteString("listen:\n")
		b.WriteString(fmt.Sprintf("  addr: \"%s\"\n\n", serverAddr))
	} else {
		b.WriteString("server:\n")
		b.WriteString(fmt.Sprintf("  addr: \"%s\"\n\n", serverAddr))
	}

	// Transport
	b.WriteString("transport:\n")
	b.WriteString(fmt.Sprintf("  protocol: \"%s\"\n", protocol))
	if role == "client" && conn > 0 {
		b.WriteString(fmt.Sprintf("  conn: %d\n", conn))
	}
	b.WriteString("  kcp:\n")
	b.WriteString(fmt.Sprintf("    mode: \"%s\"\n", kcpMode))
	b.WriteString(fmt.Sprintf("    block: \"%s\"\n", block))
	if key != "" {
		b.WriteString(fmt.Sprintf("    key: \"%s\"\n", key))
	}

	return b.String()
}

func printRecommendations(role, kcpMode, block string, conn int) {
	fmt.Println("\n📋 Optimization Recommendations:")
	fmt.Println("─────────────────────────────────")

	if role == "server" {
		fmt.Println("🖥  Server-specific:")
		fmt.Println("   • Increase PCAP sockbuf to 16MB+ for high connection counts")
		fmt.Println("   • Default rcvwnd/sndwnd set to 2048 (good for high scale)")
		fmt.Println("   • Default smuxbuf set to 8MB, streambuf to 4MB for high concurrency")
		fmt.Println("   • Consider running with 'fast2' or 'fast3' for latency-sensitive workloads")
	}

	if role == "client" {
		fmt.Println("💻 Client-specific:")
		if conn == 1 {
			fmt.Println("   • Consider conn: 2-4 for higher throughput (parallel KCP sessions)")
		}
		if conn > 8 {
			fmt.Println("   ⚠  High connection count. Each connection uses separate raw sockets.")
			fmt.Println("      Monitor system resources and consider reducing if CPU usage is high.")
		}
	}

	switch kcpMode {
	case "normal":
		fmt.Println("   ℹ  'normal' mode: conservative, good for stable networks")
		fmt.Println("   💡 Consider 'fast' for better responsiveness with minimal CPU increase")
	case "fast":
		fmt.Println("   ✅ 'fast' mode: good balance (recommended for most use cases)")
	case "fast2":
		fmt.Println("   ⚡ 'fast2' mode: aggressive retransmit, monitor CPU usage under load")
	case "fast3":
		fmt.Println("   ⚡ 'fast3' mode: most aggressive, 10ms interval — high CPU on busy links")
		fmt.Println("   💡 If CPU is a concern, 'fast2' (20ms) is nearly as responsive")
	}

	switch block {
	case "none", "null":
		fmt.Println("   ⚠  No encryption: traffic is unprotected. Use only for testing!")
	case "xor":
		fmt.Println("   ⚠  XOR encryption: very weak, suitable only for obfuscation")
	case "aes-128-gcm":
		fmt.Println("   ✅ AES-128-GCM: authenticated encryption, hardware-accelerated on modern CPUs")
	case "salsa20":
		fmt.Println("   ✅ Salsa20: fast stream cipher, good for high-throughput scenarios")
	case "3des":
		fmt.Println("   ⚠  3DES is slow and deprecated. Consider AES or Salsa20 instead.")
	case "blowfish":
		fmt.Println("   ℹ  Blowfish: adequate, but AES is generally faster on modern hardware")
	}

	fmt.Println()
	fmt.Println("🔧 General tips:")
	fmt.Println("   • Use the same encryption key and block on both client and server")
	fmt.Println("   • Set log level to 'warn' or 'error' in production for best performance")
	fmt.Println("   • Increase pcap.sockbuf if you see packet drops under heavy load")
	fmt.Println("   • Consider FEC (dshard/pshard) for very lossy networks (>5% loss)")
	fmt.Println()
}

// --- Helpers ---

func askString(reader *bufio.Reader, prompt, def string) string {
	if def != "" {
		fmt.Printf("   %s [%s]: ", prompt, def)
	} else {
		fmt.Printf("   %s: ", prompt)
	}
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func askChoice(reader *bufio.Reader, prompt string, choices []string, def string) string {
	fmt.Printf("   %s (%s) [%s]: ", prompt, strings.Join(choices, "/"), def)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	for _, c := range choices {
		if strings.EqualFold(line, c) {
			return c
		}
	}
	fmt.Printf("   Invalid choice '%s', using default '%s'\n", line, def)
	return def
}

func askInt(reader *bufio.Reader, prompt string, def, min, max int) int {
	fmt.Printf("   %s [%d]: ", prompt, def)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	v, err := strconv.Atoi(line)
	if err != nil || v < min || v > max {
		fmt.Printf("   Invalid, using default %d\n", def)
		return def
	}
	return v
}

func askYesNo(reader *bufio.Reader, prompt string, def bool) bool {
	defStr := "y/N"
	if def {
		defStr = "Y/n"
	}
	fmt.Printf("   %s [%s]: ", prompt, defStr)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return def
	}
	return line == "y" || line == "yes"
}

func listInterfaces() []net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("⚠  Could not list interfaces: %v\n", err)
		return nil
	}

	var result []net.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		result = append(result, iface)
	}
	if len(result) == 0 {
		return ifaces // fallback to all
	}
	return result
}

func getInterfaceAddrs(iface net.Interface) string {
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	var parts []string
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}
