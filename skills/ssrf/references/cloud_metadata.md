# Cloud Metadata Endpoint Reference

## AWS IMDS
- Base: `http://169.254.169.254/latest/`
- Key paths: `meta-data/`, `user-data`, `meta-data/iam/security-credentials/`
- IMDSv2 requires PUT token with `X-aws-ec2-metadata-token-ttl-seconds` header

## GCP
- Base: `http://metadata.google.internal/computeMetadata/v1/`
- Requires: `Metadata-Flavor: Google` header
- Key paths: `instance/service-accounts/default/token`, `project/attributes/ssh-keys`

## Azure
- Base: `http://169.254.169.254/metadata/`
- Requires: `Metadata: true` header + `api-version` query param
- Key paths: `instance/compute`, `identity/oauth2/token`

## DigitalOcean
- Base: `http://169.254.169.254/metadata/v1/`

## Alibaba Cloud
- Base: `http://100.100.100.200/latest/meta-data/`
