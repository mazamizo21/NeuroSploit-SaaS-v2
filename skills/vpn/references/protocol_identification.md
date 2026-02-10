# VPN Protocol Identification

## Goals
1. Identify VPN protocol and ports in use.
2. Capture service banners and certificate metadata.
3. Record tunnel endpoints and exposure scope.

## Safe Checks
1. `nmap -sU -p500,4500` for IKE/IPsec.
2. `nmap -sV -p1194,443` for OpenVPN or SSL VPN.
3. Record protocol hints without authentication.

## Evidence Checklist
1. Port map with detected protocols.
2. Banner or certificate details where available.
3. Endpoint list with protocol hints and timestamps.
