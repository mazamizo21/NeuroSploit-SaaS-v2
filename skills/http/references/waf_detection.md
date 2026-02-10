# WAF and Bot Protection

## Goals
1. Identify WAF or bot protection presence.
2. Capture vendor and response evidence.
3. Record challenge behavior and headers.

## Safe Checks
1. `wafw00f https://target`
2. `httpx` tech detection and response codes

## Indicators to Record
1. WAF vendor name.
2. Challenge pages or CAPTCHA indicators.
3. Distinct response headers or cookies tied to protection.

## Evidence Checklist
1. WAF detection output.
2. Sample response metadata and headers.
3. Notes on challenge behavior or rate limits.
