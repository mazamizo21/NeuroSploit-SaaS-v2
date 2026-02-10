package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/crypto/curve25519"
)

// RegistrationRequest matches the gateway's RegisterRequest
type RegistrationRequest struct {
	AgentID    string                 `json:"agent_id"`
	Token      string                 `json:"token"`
	Name       string                 `json:"name"`
	PublicKey  string                 `json:"public_key"`
	ClientInfo map[string]interface{} `json:"client_info,omitempty"`
}

// RegistrationResponse matches the gateway's RegisterResponse
type RegistrationResponse struct {
	GatewayPublicKey string `json:"gateway_public_key"`
	GatewayEndpoint  string `json:"gateway_endpoint"`
	AssignedIP       string `json:"assigned_ip"`
	AllowedIPs       string `json:"allowed_ips"`
	DNSServers       string `json:"dns_servers"`
	Status           string `json:"status"`
}

// AgentState persists connection state to disk
type AgentState struct {
	AgentID          string `json:"agent_id"`
	GatewayURL       string `json:"gateway_url"`
	PrivateKey       string `json:"private_key"`
	PublicKey        string `json:"public_key"`
	GatewayPublicKey string `json:"gateway_public_key"`
	GatewayEndpoint  string `json:"gateway_endpoint"`
	AssignedIP       string `json:"assigned_ip"`
	AllowedIPs       string `json:"allowed_ips"`
	ConnectedAt      string `json:"connected_at"`
}

func connectAgent(token, gatewayURL string) error {
	fmt.Println("🔗 TazoSploit Agent — Connecting...")
	fmt.Printf("   Gateway: %s\n", gatewayURL)

	// Generate WireGuard keypair for this agent
	privKey, pubKey, err := generateKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate keys: %w", err)
	}
	fmt.Printf("   Public Key: %s\n", pubKey[:20]+"...")

	// Get hostname for agent name
	hostname, _ := os.Hostname()
	agentID := fmt.Sprintf("agent-%s-%d", hostname, time.Now().Unix())

	// Gather client info
	clientInfo := map[string]interface{}{
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"hostname": hostname,
		"version":  version,
	}

	// Register with gateway
	regReq := RegistrationRequest{
		AgentID:    agentID,
		Token:      token,
		Name:       hostname,
		PublicKey:  pubKey,
		ClientInfo: clientInfo,
	}

	regData, _ := json.Marshal(regReq)
	resp, err := http.Post(
		gatewayURL+"/api/v1/tunnel/register",
		"application/json",
		bytes.NewReader(regData),
	)
	if err != nil {
		return fmt.Errorf("failed to register with gateway: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("registration failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var regResp RegistrationResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Printf("   Assigned IP: %s\n", regResp.AssignedIP)
	fmt.Printf("   Gateway Endpoint: %s\n", regResp.GatewayEndpoint)
	fmt.Println("   Status: ✅ Registered")

	// Save state to disk
	state := AgentState{
		AgentID:          agentID,
		GatewayURL:       gatewayURL,
		PrivateKey:       privKey,
		PublicKey:        pubKey,
		GatewayPublicKey: regResp.GatewayPublicKey,
		GatewayEndpoint:  regResp.GatewayEndpoint,
		AssignedIP:       regResp.AssignedIP,
		AllowedIPs:       regResp.AllowedIPs,
		ConnectedAt:      time.Now().Format(time.RFC3339),
	}
	saveState(&state)

	// Try to set up WireGuard tunnel
	tunnelErr := setupTunnel(&state)
	if tunnelErr != nil {
		fmt.Printf("\n⚠️  WireGuard tunnel setup failed: %v\n", tunnelErr)
		fmt.Println("   The agent is registered but tunnel is not active.")
		fmt.Println("   You may need to run with elevated privileges (sudo) or install WireGuard tools.")
		fmt.Println("\n   Manual WireGuard config:")
		printWGConfig(&state)
	} else {
		fmt.Println("\n✅ Connected! Tunnel active.")
		fmt.Printf("   Your tunnel IP: %s\n", regResp.AssignedIP)
		fmt.Println("   Press Ctrl+C to disconnect.")
	}

	// Start heartbeat loop
	fmt.Println("\n📡 Sending heartbeats...")
	return heartbeatLoop(agentID, gatewayURL)
}

func heartbeatLoop(agentID, gatewayURL string) error {
	// Set up signal handler for clean disconnect
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := sendHeartbeat(agentID, gatewayURL); err != nil {
				fmt.Printf("⚠️  Heartbeat failed: %v\n", err)
			}
		case sig := <-sigCh:
			fmt.Printf("\n📴 Received %v — disconnecting...\n", sig)
			teardownTunnel()
			removeState()
			fmt.Println("✅ Disconnected. Goodbye!")
			return nil
		}
	}
}

func printWGConfig(state *AgentState) {
	fmt.Printf(`
[Interface]
PrivateKey = %s
Address = %s/32

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = 25
`, state.PrivateKey, state.AssignedIP, state.GatewayPublicKey, state.GatewayEndpoint, state.AllowedIPs)
}

func generateKeypair() (privateKey, publicKey string, err error) {
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return "", "", err
	}

	// Clamp per WireGuard spec
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)

	return base64.StdEncoding.EncodeToString(privKey[:]),
		base64.StdEncoding.EncodeToString(pubKey[:]), nil
}

func stateFilePath() string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".tazosploit")
	os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "agent-state.json")
}

func saveState(state *AgentState) {
	data, _ := json.MarshalIndent(state, "", "  ")
	os.WriteFile(stateFilePath(), data, 0600)
}

func loadState() (*AgentState, error) {
	data, err := os.ReadFile(stateFilePath())
	if err != nil {
		return nil, err
	}
	var state AgentState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func removeState() {
	os.Remove(stateFilePath())
}
