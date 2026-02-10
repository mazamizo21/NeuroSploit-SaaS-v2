# AWS Logging and Monitoring

## Goals
1. Confirm CloudTrail, Config, and CloudWatch coverage.
2. Identify gaps in audit logging.
3. Record retention and multi-region settings.

## Safe Checks
1. `aws cloudtrail describe-trails`
2. `aws configservice describe-configuration-recorders`
3. `aws logs describe-log-groups`
4. `aws cloudtrail get-trail-status --name <trail>` (authorized)

## Indicators to Record
1. CloudTrail not enabled in all regions.
2. Config recorder disabled.
3. No centralized log retention.
4. Log groups without retention settings.

## Evidence Checklist
1. Trail list and regions.
2. Config recorder status.
3. Log group count and retention settings.
4. Trail status output for enabled trails.
