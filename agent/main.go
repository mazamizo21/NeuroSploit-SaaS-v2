package main

import (
	"fmt"
	"os"
	"strings"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "connect":
		token := ""
		gatewayURL := ""
		for i := 2; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--token":
				if i+1 < len(os.Args) {
					token = os.Args[i+1]
					i++
				}
			case "--gateway":
				if i+1 < len(os.Args) {
					gatewayURL = os.Args[i+1]
					i++
				}
			}
		}
		if token == "" {
			fmt.Println("Error: --token is required")
			fmt.Println("Usage: tazosploit-agent connect --token <token> [--gateway <url>]")
			os.Exit(1)
		}
		if gatewayURL == "" {
			gatewayURL = os.Getenv("TAZOSPLOIT_GATEWAY")
			if gatewayURL == "" {
				gatewayURL = "http://localhost:8080"
			}
		}
		// Remove trailing slash
		gatewayURL = strings.TrimRight(gatewayURL, "/")
		
		if err := connectAgent(token, gatewayURL); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "status":
		if err := showStatus(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "disconnect":
		if err := disconnectAgent(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "version":
		fmt.Printf("tazosploit-agent v%s\n", version)

	case "help", "--help", "-h":
		printUsage()

	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`TazoSploit Agent v%s
Secure tunnel agent for internal network pentesting

Usage:
  tazosploit-agent <command> [options]

Commands:
  connect      Connect to TazoSploit platform
  status       Show connection status
  disconnect   Disconnect and clean up
  version      Show version
  help         Show this help

Connect Options:
  --token <token>      One-time connection token (required)
  --gateway <url>      Gateway URL (default: $TAZOSPLOIT_GATEWAY or http://localhost:8080)

Environment Variables:
  TAZOSPLOIT_GATEWAY   Default gateway URL

Examples:
  tazosploit-agent connect --token tsploit_abc123def456
  tazosploit-agent connect --token tsploit_abc123 --gateway https://gateway.tazosploit.com:8080
  tazosploit-agent status
  tazosploit-agent disconnect
`, version)
}
