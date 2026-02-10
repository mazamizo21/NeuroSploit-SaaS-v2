package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func sendHeartbeat(agentID, gatewayURL string) error {
	data, _ := json.Marshal(map[string]string{"agent_id": agentID})
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(
		gatewayURL+"/api/v1/tunnel/heartbeat",
		"application/json",
		bytes.NewReader(data),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("heartbeat returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func showStatus() error {
	state, err := loadState()
	if err != nil {
		fmt.Println("❌ Not connected")
		fmt.Println("   Run: tazosploit-agent connect --token <token>")
		return nil
	}

	fmt.Println("📡 TazoSploit Agent Status")
	fmt.Printf("   Agent ID:    %s\n", state.AgentID)
	fmt.Printf("   Gateway:     %s\n", state.GatewayURL)
	fmt.Printf("   Tunnel IP:   %s\n", state.AssignedIP)
	fmt.Printf("   Connected:   %s\n", state.ConnectedAt)
	fmt.Printf("   Gateway Key: %s...\n", state.GatewayPublicKey[:20])

	// Try to ping the gateway heartbeat endpoint
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(state.GatewayURL + "/health")
	if err != nil {
		fmt.Println("   Gateway:     ❌ Unreachable")
	} else {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			fmt.Println("   Gateway:     ✅ Reachable")
		} else {
			fmt.Printf("   Gateway:     ⚠️  HTTP %d\n", resp.StatusCode)
		}
	}

	return nil
}

func disconnectAgent() error {
	state, err := loadState()
	if err != nil {
		fmt.Println("❌ Not connected — nothing to disconnect")
		return nil
	}

	fmt.Printf("📴 Disconnecting agent %s...\n", state.AgentID)

	// Tear down tunnel
	teardownTunnel()

	// Remove state file
	removeState()

	fmt.Println("✅ Disconnected successfully")
	return nil
}
