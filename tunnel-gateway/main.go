package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// Config holds gateway configuration
type Config struct {
	WGListenPort int    `json:"wg_listen_port"`
	APIListenAddr string `json:"api_listen_addr"`
	WGSubnet     string `json:"wg_subnet"` // e.g. "10.100.0.0/16"
	WGEndpoint   string `json:"wg_endpoint"` // public endpoint for clients
	DataDir      string `json:"data_dir"`
}

var (
	config  Config
	gateway *WGGateway
	mu      sync.RWMutex
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("TazoSploit Tunnel Gateway starting...")

	// Load configuration
	config = Config{
		WGListenPort:  getEnvInt("WG_LISTEN_PORT", 51820),
		APIListenAddr: getEnvStr("API_LISTEN_ADDR", ":8080"),
		WGSubnet:      getEnvStr("WG_SUBNET", "10.100.0.0/16"),
		WGEndpoint:    getEnvStr("WG_ENDPOINT", ""),
		DataDir:       getEnvStr("DATA_DIR", "/etc/wireguard"),
	}

	configJSON, _ := json.MarshalIndent(config, "", "  ")
	log.Printf("Configuration: %s", configJSON)

	// Initialize WireGuard gateway
	var err error
	gateway, err = NewWGGateway(config)
	if err != nil {
		log.Fatalf("Failed to initialize WireGuard gateway: %v", err)
	}
	log.Println("WireGuard gateway initialized")

	// Start REST API server
	apiServer := NewAPIServer(gateway)
	go func() {
		log.Printf("API server listening on %s", config.APIListenAddr)
		if err := http.ListenAndServe(config.APIListenAddr, apiServer.Router()); err != nil {
			log.Fatalf("API server failed: %v", err)
		}
	}()

	log.Println("Tunnel Gateway ready")

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	gateway.Shutdown()
}

func getEnvStr(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		var v int
		fmt.Sscanf(val, "%d", &v)
		if v > 0 {
			return v
		}
	}
	return defaultVal
}
