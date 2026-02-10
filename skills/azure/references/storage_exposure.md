# Azure Storage Exposure

## Goals
1. Identify public storage accounts or containers.
2. Capture network and encryption posture.
3. Record secure transfer and logging status.

## Safe Checks
1. `az storage account list`
2. `az storage account show --name <account>` (authorized)
3. `az storage account blob-service-properties show` (authorized)

## Indicators to Record
1. Public network access enabled.
2. Blob anonymous access allowed.
3. Missing secure transfer requirement.
4. Logging or versioning disabled for sensitive data.

## Evidence Checklist
1. Storage account list and regions.
2. Public access flags and network rules.
3. Secure transfer and logging settings.
