# GCP Network Exposure

## Goals
1. Identify public IPs, open firewall rules, and exposed services.
2. Capture network posture without modifying rules.
3. Record load balancer and forwarding rule exposure.

## Safe Checks
1. `gcloud compute firewall-rules list --format=json`
2. `gcloud compute instances list --format=json`
3. `gcloud compute forwarding-rules list --format=json`

## Indicators to Record
1. 0.0.0.0/0 ingress on sensitive ports.
2. Instances with external IPs tied to permissive firewall rules.
3. Public forwarding rules without backend restrictions.

## Evidence Checklist
1. Firewall rule summary.
2. External IP count and sample instances.
3. Forwarding rule exposure evidence.
