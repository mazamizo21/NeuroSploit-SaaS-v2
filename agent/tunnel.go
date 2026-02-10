package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// setupTunnel creates a WireGuard tunnel using wg-quick or manual commands
func setupTunnel(state *AgentState) error {
	// Generate WireGuard config
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = 25
`, state.PrivateKey, state.AssignedIP, state.GatewayPublicKey, state.GatewayEndpoint, state.AllowedIPs)

	switch runtime.GOOS {
	case "linux":
		return setupTunnelLinux(conf)
	case "darwin":
		return setupTunnelDarwin(conf)
	default:
		return fmt.Errorf("automatic tunnel setup not supported on %s — use manual config", runtime.GOOS)
	}
}

func setupTunnelLinux(conf string) error {
	// Try wg-quick first
	confFile := "/tmp/tazosploit-wg0.conf"
	if err := writeFile(confFile, conf); err != nil {
		return err
	}

	// Bring down if exists
	exec.Command("wg-quick", "down", confFile).Run()

	cmd := exec.Command("wg-quick", "up", confFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try manual approach
		return setupTunnelManual(conf)
	}
	_ = output
	return nil
}

func setupTunnelDarwin(conf string) error {
	// macOS: try using wireguard-go userspace if available
	confFile := "/tmp/tazosploit-wg0.conf"
	if err := writeFile(confFile, conf); err != nil {
		return err
	}

	// Check if wg-quick is available (via Homebrew wireguard-tools)
	if path, err := exec.LookPath("wg-quick"); err == nil {
		_ = path
		exec.Command("wg-quick", "down", confFile).Run()
		cmd := exec.Command("wg-quick", "up", confFile)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("wg-quick failed: %v — %s", err, string(output))
		}
		return nil
	}

	return fmt.Errorf("WireGuard tools not found. Install with: brew install wireguard-tools")
}

func setupTunnelManual(conf string) error {
	// Manual approach using ip and wg commands
	// Parse config to extract values
	lines := strings.Split(conf, "\n")
	var privKey, address, peerPubKey, endpoint, allowedIPs string

	section := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "[Interface]" {
			section = "interface"
		} else if line == "[Peer]" {
			section = "peer"
		} else if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			switch {
			case section == "interface" && key == "PrivateKey":
				privKey = val
			case section == "interface" && key == "Address":
				address = val
			case section == "peer" && key == "PublicKey":
				peerPubKey = val
			case section == "peer" && key == "Endpoint":
				endpoint = val
			case section == "peer" && key == "AllowedIPs":
				allowedIPs = val
			}
		}
	}

	// Create interface
	exec.Command("ip", "link", "del", "tazosploit0").Run()
	if out, err := exec.Command("ip", "link", "add", "tazosploit0", "type", "wireguard").CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create interface: %v — %s", err, string(out))
	}

	// Write private key to temp file
	keyFile := "/tmp/tazosploit-wg-privkey"
	writeFile(keyFile, privKey)

	// Set private key
	exec.Command("wg", "set", "tazosploit0", "private-key", keyFile).Run()

	// Add peer
	exec.Command("wg", "set", "tazosploit0", "peer", peerPubKey,
		"endpoint", endpoint, "allowed-ips", allowedIPs,
		"persistent-keepalive", "25").Run()

	// Set address and bring up
	exec.Command("ip", "addr", "add", address, "dev", "tazosploit0").Run()
	exec.Command("ip", "link", "set", "tazosploit0", "up").Run()

	// Add route
	exec.Command("ip", "route", "add", allowedIPs, "dev", "tazosploit0").Run()

	return nil
}

// teardownTunnel removes the WireGuard tunnel
func teardownTunnel() {
	switch runtime.GOOS {
	case "linux":
		exec.Command("wg-quick", "down", "/tmp/tazosploit-wg0.conf").Run()
		exec.Command("ip", "link", "del", "tazosploit0").Run()
	case "darwin":
		exec.Command("wg-quick", "down", "/tmp/tazosploit-wg0.conf").Run()
	}
	// Clean up temp files
	exec.Command("rm", "-f", "/tmp/tazosploit-wg0.conf", "/tmp/tazosploit-wg-privkey").Run()
}

func writeFile(path, content string) error {
	return exec.Command("sh", "-c", fmt.Sprintf("echo '%s' > %s && chmod 600 %s", content, path, path)).Run()
}
