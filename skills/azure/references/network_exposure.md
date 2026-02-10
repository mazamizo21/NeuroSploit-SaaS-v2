# Azure Network Exposure

## Goals
1. Identify public IPs, open NSGs, and exposed VMs.
2. Capture inbound exposure without modifying rules.
3. Record application gateways and load balancer exposure.

## Safe Checks
1. `az network public-ip list`
2. `az network nsg list`
3. `az vm list-ip-addresses`
4. `az network lb list` (authorized)

## Indicators to Record
1. NSG rules with 0.0.0.0/0 inbound on sensitive ports.
2. VMs with public IPs and broad NSG rules.
3. Public load balancers with open listener ports.

## Evidence Checklist
1. Public IP count.
2. NSG rule summaries.
3. VM exposure notes.
4. Load balancer exposure evidence.
