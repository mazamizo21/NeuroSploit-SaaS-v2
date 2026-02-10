# AWS Network Exposure

## Goals
1. Identify public-facing security groups and internet gateways.
2. Capture inbound exposure without modifying rules.
3. Record load balancer exposure and public IPs.

## Safe Checks
1. `aws ec2 describe-security-groups`
2. `aws ec2 describe-network-interfaces`
3. `aws ec2 describe-internet-gateways`
4. `aws elb describe-load-balancers` (classic) or `aws elbv2 describe-load-balancers`

## Indicators to Record
1. 0.0.0.0/0 or ::/0 inbound rules on sensitive ports.
2. Security groups attached to public IPs.
3. Load balancers with public-facing schemes.

## Evidence Checklist
1. Security group counts.
2. List of open ports by group (summary).
3. Internet gateway attachments.
4. Public-facing load balancer list.
