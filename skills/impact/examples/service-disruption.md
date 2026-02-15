# Service Disruption Proof

## Scenario
Root access, authorized to demonstrate service disruption capability.

## Step 1: Baseline Service State
```bash
root@target:~# systemctl status nginx | head -5
● nginx.service - A high performance web server
     Loaded: loaded (/lib/systemd/system/nginx.service; enabled)
     Active: active (running) since Mon 2024-12-01 03:00:00 EST; 45 days ago
   Main PID: 1234 (nginx)
      Tasks: 5 (limit: 4915)

root@target:~# curl -s -o /dev/null -w "Response: %{http_code} Time: %{time_total}s\n" http://localhost/
Response: 200 Time: 0.002s
```

## Step 2: Demonstrate Stop Capability
```bash
root@target:~# systemctl stop nginx
root@target:~# systemctl status nginx | head -3
● nginx.service - A high performance web server
     Loaded: loaded (/lib/systemd/system/nginx.service; enabled)
     Active: inactive (dead) since Wed 2025-01-15 20:15:00 EST; 2s ago

root@target:~# curl -s -o /dev/null -w "Response: %{http_code}\n" http://localhost/ 2>/dev/null || echo "Connection refused ✅"
Connection refused ✅
```

## Step 3: IMMEDIATELY Restore
```bash
root@target:~# systemctl start nginx
root@target:~# systemctl status nginx | head -3
● nginx.service - A high performance web server
     Loaded: loaded (/lib/systemd/system/nginx.service; enabled)
     Active: active (running) since Wed 2025-01-15 20:15:05 EST; 1s ago

root@target:~# curl -s -o /dev/null -w "Response: %{http_code} Time: %{time_total}s\n" http://localhost/
Response: 200 Time: 0.003s
# Service restored ✅ — total downtime: ~5 seconds
```

## Step 4: Document Capability
```bash
root@target:~# echo "=== SERVICE DISRUPTION PROOF ===" > /tmp/service_impact.txt
root@target:~# echo "Target: nginx (web server)" >> /tmp/service_impact.txt
root@target:~# echo "Access level: root" >> /tmp/service_impact.txt
root@target:~# echo "Action: systemctl stop → start" >> /tmp/service_impact.txt
root@target:~# echo "Downtime: ~5 seconds (controlled)" >> /tmp/service_impact.txt
root@target:~# echo "Impact: Full web service outage during downtime" >> /tmp/service_impact.txt
root@target:~# echo "Remediation: Limit root access, service monitoring, auto-restart" >> /tmp/service_impact.txt
```

## Evidence
- Service stopped and restarted within 5 seconds
- HTTP 200 before and after — service fully restored
- Demonstrates: root access = ability to disrupt any service
- Remediation: principle of least privilege, service monitoring, watchdog timers
