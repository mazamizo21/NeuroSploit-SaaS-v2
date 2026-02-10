package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// APIServer handles REST API requests for the tunnel gateway
type APIServer struct {
	gw *WGGateway
}

// RegisterRequest is the request body for agent registration
type RegisterRequest struct {
	AgentID    string                 `json:"agent_id"`
	Token      string                 `json:"token"`
	Name       string                 `json:"name"`
	PublicKey  string                 `json:"public_key"`
	ClientInfo map[string]interface{} `json:"client_info,omitempty"`
}

// RegisterResponse is the response body after registration
type RegisterResponse struct {
	GatewayPublicKey string `json:"gateway_public_key"`
	GatewayEndpoint  string `json:"gateway_endpoint"`
	AssignedIP       string `json:"assigned_ip"`
	AllowedIPs       string `json:"allowed_ips"`
	DNSServers       string `json:"dns_servers"`
	Status           string `json:"status"`
}

// HeartbeatRequest is the request body for heartbeat
type HeartbeatRequest struct {
	AgentID string `json:"agent_id"`
}

// PeerResponse is a peer status response
type PeerResponse struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	AssignedIP    string                 `json:"assigned_ip"`
	Status        string                 `json:"status"`
	LastHeartbeat string                 `json:"last_heartbeat"`
	ClientInfo    map[string]interface{} `json:"client_info,omitempty"`
	CreatedAt     string                 `json:"created_at"`
}

// NewAPIServer creates a new API server
func NewAPIServer(gw *WGGateway) *APIServer {
	return &APIServer{gw: gw}
}

// Router returns the HTTP router for the API server
func (s *APIServer) Router() http.Handler {
	mux := http.NewServeMux()

	// Health
	mux.HandleFunc("/health", s.handleHealth)

	// Agent registration (called by agent binary)
	mux.HandleFunc("/api/v1/tunnel/register", s.handleRegister)

	// Heartbeat
	mux.HandleFunc("/api/v1/tunnel/heartbeat", s.handleHeartbeat)

	// Peer management (called by control plane)
	mux.HandleFunc("/api/v1/tunnel/peers", s.handlePeers)
	mux.HandleFunc("/api/v1/tunnel/peers/", s.handlePeerByID)

	// Gateway info
	mux.HandleFunc("/api/v1/tunnel/info", s.handleInfo)

	// Add CORS and logging middleware
	return corsMiddleware(loggingMiddleware(mux))
}

func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]interface{}{
		"status":  "healthy",
		"service": "tunnel-gateway",
		"time":    time.Now().UTC().Format(time.RFC3339),
		"peers":   len(s.gw.ListPeers()),
	})
}

func (s *APIServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid request body"})
		return
	}

	if req.AgentID == "" || req.PublicKey == "" {
		writeJSON(w, 400, map[string]string{"error": "agent_id and public_key are required"})
		return
	}

	peer, err := s.gw.RegisterPeer(req.AgentID, req.Name, req.PublicKey, req.ClientInfo)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	resp := RegisterResponse{
		GatewayPublicKey: s.gw.GetPublicKey(),
		GatewayEndpoint:  s.gw.GetEndpoint(),
		AssignedIP:       peer.AssignedIP,
		AllowedIPs:       "10.100.0.0/16",
		DNSServers:       "10.100.0.1",
		Status:           "registered",
	}

	log.Printf("Agent registered: %s (%s) → %s", req.Name, req.AgentID, peer.AssignedIP)
	writeJSON(w, 200, resp)
}

func (s *APIServer) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}

	var req HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid request body"})
		return
	}

	if err := s.gw.Heartbeat(req.AgentID); err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *APIServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		peers := s.gw.ListPeers()
		resp := make([]PeerResponse, 0, len(peers))
		for _, p := range peers {
			resp = append(resp, peerToResponse(p))
		}
		writeJSON(w, 200, resp)

	case "DELETE":
		// Bulk delete — not implemented, use /peers/{id}
		writeJSON(w, 405, map[string]string{"error": "use DELETE /api/v1/tunnel/peers/{id}"})

	default:
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
	}
}

func (s *APIServer) handlePeerByID(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path: /api/v1/tunnel/peers/{id}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/tunnel/peers/"), "/")
	id := parts[0]
	if id == "" {
		writeJSON(w, 400, map[string]string{"error": "peer ID required"})
		return
	}

	switch r.Method {
	case "GET":
		peer, ok := s.gw.GetPeer(id)
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "peer not found"})
			return
		}
		writeJSON(w, 200, peerToResponse(peer))

	case "DELETE":
		if err := s.gw.RemovePeer(id); err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "removed"})

	default:
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
	}
}

func (s *APIServer) handleInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]interface{}{
		"public_key": s.gw.GetPublicKey(),
		"endpoint":   s.gw.GetEndpoint(),
		"subnet":     s.gw.config.WGSubnet,
		"peers":      len(s.gw.ListPeers()),
	})
}

// Helper functions

func peerToResponse(p *Peer) PeerResponse {
	return PeerResponse{
		ID:            p.ID,
		Name:          p.Name,
		AssignedIP:    p.AssignedIP,
		Status:        p.Status,
		LastHeartbeat: p.LastHeartbeat.Format(time.RFC3339),
		ClientInfo:    p.ClientInfo,
		CreatedAt:     p.CreatedAt.Format(time.RFC3339),
	}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(200)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s %v", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// Ensure fmt is used
var _ = fmt.Sprintf
