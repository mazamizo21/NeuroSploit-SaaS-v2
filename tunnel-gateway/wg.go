package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Peer represents a registered WireGuard peer (agent)
type Peer struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	PublicKey     string    `json:"public_key"`
	AssignedIP    string    `json:"assigned_ip"`
	AllowedIPs    string    `json:"allowed_ips"`
	Status        string    `json:"status"` // pending, connected, disconnected
	LastHeartbeat time.Time `json:"last_heartbeat"`
	ClientInfo    map[string]interface{} `json:"client_info,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// WGGateway manages the WireGuard interface and peers
type WGGateway struct {
	config     Config
	privateKey string
	publicKey  string
	peers      map[string]*Peer // keyed by ID
	ipCounter  int              // tracks next available IP
	mu         sync.RWMutex
	dataDir    string
}

// NewWGGateway creates and initializes the WireGuard gateway
func NewWGGateway(cfg Config) (*WGGateway, error) {
	gw := &WGGateway{
		config:    cfg,
		peers:     make(map[string]*Peer),
		ipCounter: 1, // start at 10.100.0.1 (gateway), agents start at .2
		dataDir:   cfg.DataDir,
	}

	// Ensure data directory exists
	os.MkdirAll(gw.dataDir, 0700)

	// Load or generate keys
	if err := gw.loadOrGenerateKeys(); err != nil {
		return nil, fmt.Errorf("key setup failed: %w", err)
	}

	// Load existing peers from disk
	gw.loadPeers()

	// Setup WireGuard interface
	if err := gw.setupInterface(); err != nil {
		log.Printf("WARNING: WireGuard interface setup failed (may need NET_ADMIN): %v", err)
		log.Println("Gateway will operate in API-only mode — WG config will be generated but not applied")
	}

	// Start heartbeat checker
	go gw.heartbeatChecker()

	return gw, nil
}

func (gw *WGGateway) loadOrGenerateKeys() error {
	keyFile := filepath.Join(gw.dataDir, "private.key")
	pubFile := filepath.Join(gw.dataDir, "public.key")

	privData, err := os.ReadFile(keyFile)
	if err == nil {
		gw.privateKey = strings.TrimSpace(string(privData))
		pubData, _ := os.ReadFile(pubFile)
		gw.publicKey = strings.TrimSpace(string(pubData))
		log.Println("Loaded existing WireGuard keys")
		return nil
	}

	// Generate new keypair
	priv, pub, err := generateWGKeypair()
	if err != nil {
		return err
	}
	gw.privateKey = priv
	gw.publicKey = pub

	os.WriteFile(keyFile, []byte(priv+"\n"), 0600)
	os.WriteFile(pubFile, []byte(pub+"\n"), 0644)

	log.Printf("Generated new WireGuard keypair (public: %s)", pub)
	return nil
}

func (gw *WGGateway) setupInterface() error {
	// Write WireGuard config
	confPath := filepath.Join(gw.dataDir, "wg0.conf")
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.100.0.1/16
ListenPort = %d
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
`, gw.privateKey, gw.config.WGListenPort)

	// Add existing peers
	gw.mu.RLock()
	for _, peer := range gw.peers {
		if peer.PublicKey != "" {
			conf += fmt.Sprintf(`
[Peer]
PublicKey = %s
AllowedIPs = %s/32
`, peer.PublicKey, peer.AssignedIP)
		}
	}
	gw.mu.RUnlock()

	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		return fmt.Errorf("failed to write wg config: %w", err)
	}

	// Try to bring up the interface
	// First, bring down if exists
	exec.Command("wg-quick", "down", "wg0").Run()

	cmd := exec.Command("wg-quick", "up", confPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick up failed: %v — %s", err, string(output))
	}

	log.Println("WireGuard interface wg0 is up")
	return nil
}

// RegisterPeer adds a new peer to the WireGuard gateway
func (gw *WGGateway) RegisterPeer(id, name, clientPubKey string, clientInfo map[string]interface{}) (*Peer, error) {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	// Check if already registered
	if existing, ok := gw.peers[id]; ok {
		// Update existing peer's public key if provided
		if clientPubKey != "" {
			existing.PublicKey = clientPubKey
			existing.Status = "connected"
			existing.LastHeartbeat = time.Now()
			existing.ClientInfo = clientInfo
			gw.savePeers()
			gw.reloadConfig()
			return existing, nil
		}
		return existing, nil
	}

	// Assign next available IP
	gw.ipCounter++
	assignedIP := fmt.Sprintf("10.100.%d.%d", gw.ipCounter/256, gw.ipCounter%256)

	peer := &Peer{
		ID:            id,
		Name:          name,
		PublicKey:      clientPubKey,
		AssignedIP:    assignedIP,
		AllowedIPs:    assignedIP + "/32",
		Status:        "connected",
		LastHeartbeat: time.Now(),
		ClientInfo:    clientInfo,
		CreatedAt:     time.Now(),
	}

	gw.peers[id] = peer
	gw.savePeers()

	// Apply to WireGuard (add peer dynamically)
	gw.reloadConfig()

	log.Printf("Registered peer %s (%s) → %s", name, id, assignedIP)
	return peer, nil
}

// RemovePeer removes a peer from the gateway
func (gw *WGGateway) RemovePeer(id string) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	peer, ok := gw.peers[id]
	if !ok {
		return fmt.Errorf("peer %s not found", id)
	}

	// Remove from WireGuard if has a public key
	if peer.PublicKey != "" {
		exec.Command("wg", "set", "wg0", "peer", peer.PublicKey, "remove").Run()
	}

	delete(gw.peers, id)
	gw.savePeers()

	log.Printf("Removed peer %s (%s)", peer.Name, id)
	return nil
}

// Heartbeat updates a peer's last heartbeat time
func (gw *WGGateway) Heartbeat(id string) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	peer, ok := gw.peers[id]
	if !ok {
		return fmt.Errorf("peer %s not found", id)
	}

	peer.LastHeartbeat = time.Now()
	peer.Status = "connected"
	return nil
}

// GetPeer returns a peer by ID
func (gw *WGGateway) GetPeer(id string) (*Peer, bool) {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	peer, ok := gw.peers[id]
	return peer, ok
}

// ListPeers returns all peers
func (gw *WGGateway) ListPeers() []*Peer {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	peers := make([]*Peer, 0, len(gw.peers))
	for _, p := range gw.peers {
		peers = append(peers, p)
	}
	return peers
}

// GetPublicKey returns the gateway's public key
func (gw *WGGateway) GetPublicKey() string {
	return gw.publicKey
}

// GetEndpoint returns the gateway's WireGuard endpoint
func (gw *WGGateway) GetEndpoint() string {
	if gw.config.WGEndpoint != "" {
		return gw.config.WGEndpoint
	}
	// Try to detect public IP
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return fmt.Sprintf("%s:%d", ipnet.IP.String(), gw.config.WGListenPort)
		}
	}
	return fmt.Sprintf("0.0.0.0:%d", gw.config.WGListenPort)
}

func (gw *WGGateway) reloadConfig() {
	// Add/update peers dynamically via wg command (no restart needed)
	for _, peer := range gw.peers {
		if peer.PublicKey != "" {
			cmd := exec.Command("wg", "set", "wg0", "peer", peer.PublicKey,
				"allowed-ips", peer.AssignedIP+"/32")
			if output, err := cmd.CombinedOutput(); err != nil {
				log.Printf("WARNING: Failed to add peer %s: %v — %s", peer.ID, err, string(output))
			} else {
				log.Printf("Added/updated WireGuard peer %s (%s)", peer.Name, peer.AssignedIP)
			}
		}
	}
	// Also update the config file for persistence
	gw.writeConfigFile()
}

func (gw *WGGateway) writeConfigFile() {
	confPath := filepath.Join(gw.dataDir, "wg0.conf")
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.100.0.1/16
ListenPort = %d
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
`, gw.privateKey, gw.config.WGListenPort)

	for _, peer := range gw.peers {
		if peer.PublicKey != "" {
			conf += fmt.Sprintf(`
[Peer]
PublicKey = %s
AllowedIPs = %s/32
`, peer.PublicKey, peer.AssignedIP)
		}
	}

	os.WriteFile(confPath, []byte(conf), 0600)
}

func (gw *WGGateway) savePeers() {
	data, _ := json.MarshalIndent(gw.peers, "", "  ")
	os.WriteFile(filepath.Join(gw.dataDir, "peers.json"), data, 0600)
}

func (gw *WGGateway) loadPeers() {
	data, err := os.ReadFile(filepath.Join(gw.dataDir, "peers.json"))
	if err != nil {
		return
	}
	json.Unmarshal(data, &gw.peers)

	// Recalculate ipCounter
	for _, p := range gw.peers {
		parts := strings.Split(p.AssignedIP, ".")
		if len(parts) == 4 {
			var a, b int
			fmt.Sscanf(parts[2], "%d", &a)
			fmt.Sscanf(parts[3], "%d", &b)
			counter := a*256 + b
			if counter > gw.ipCounter {
				gw.ipCounter = counter
			}
		}
	}

	log.Printf("Loaded %d existing peers", len(gw.peers))
}

func (gw *WGGateway) heartbeatChecker() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		gw.mu.Lock()
		for _, peer := range gw.peers {
			if peer.Status == "connected" && time.Since(peer.LastHeartbeat) > 2*time.Minute {
				peer.Status = "disconnected"
				log.Printf("Peer %s (%s) marked disconnected (no heartbeat)", peer.Name, peer.ID)
			}
		}
		gw.mu.Unlock()
	}
}

// Shutdown cleans up the WireGuard interface
func (gw *WGGateway) Shutdown() {
	exec.Command("wg-quick", "down", "wg0").Run()
	log.Println("WireGuard interface shut down")
}

// generateWGKeypair generates a WireGuard-compatible Curve25519 keypair
func generateWGKeypair() (privateKey, publicKey string, err error) {
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Clamp the private key per WireGuard spec
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)

	return base64.StdEncoding.EncodeToString(privKey[:]),
		base64.StdEncoding.EncodeToString(pubKey[:]), nil
}
