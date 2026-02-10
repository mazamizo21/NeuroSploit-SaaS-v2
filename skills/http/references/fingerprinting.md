# HTTP Fingerprinting

## Goals
1. Identify server, framework, and platform indicators.
2. Capture banners and response headers safely.
3. Record confidence notes for each fingerprint.

## Safe Checks
1. `httpx -json` with `-title -tech-detect -web-server`
2. `whatweb -a 3` for high-confidence fingerprints
3. Capture response headers and title for correlation.

## Evidence Checklist
1. Detected tech stack list with source tool.
2. Server header and response title.
3. Sample response headers and status codes.
