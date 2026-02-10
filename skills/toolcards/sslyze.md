# sslyze Toolcard

## Overview
- Summary: SSLyze is a fast TLS configuration scanner that can produce structured outputs.

## Advanced Techniques
- Use JSON output for ingestion into evidence pipelines.
- Scan non-HTTP services with STARTTLS support when applicable.

## Safe Defaults
- Rate limits: conservative concurrency for external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: tls_report.json

## References
- https://github.com/nabla-c0d3/sslyze
