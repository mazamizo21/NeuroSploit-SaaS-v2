# Evidence Capture

## Goals
1. Capture key outputs for reporting and reproducibility.
2. Maintain consistent naming and timestamps.
3. Keep raw outputs alongside parsed summaries.

## Evidence Checklist
1. Nmap outputs (`-oN`, `-oG`, `-oX`) with command lines and timing profiles.
2. Host and port inventory (`recon_hosts.json`), plus `services.json` with version hints.
3. HTTP discovery outputs (`httpx` JSONL) and summarized endpoints.
4. DNS enumeration outputs (subdomain lists, resolution results).
5. Screenshot references if authorized (path list and timestamps).

## Evidence Mapping
1. `recon_hosts.json`: host, port, proto, state, and service name.
2. `services.json`: service inventory with versions and confidence notes.
3. `endpoints.json`: URL, status code, title, and tech hints.
4. `evidence.json`: raw output files, command lines, and timestamps.
