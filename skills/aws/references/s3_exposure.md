# S3 Exposure Review

## Goals
1. Identify public or overly permissive buckets.
2. Capture encryption and policy posture.
3. Record access logging and versioning state.

## Safe Checks
1. `aws s3api list-buckets`
2. `aws s3api get-public-access-block --bucket <name>` (authorized)
3. `aws s3api get-bucket-policy-status --bucket <name>` (authorized)
4. `aws s3api get-bucket-encryption --bucket <name>` (authorized)
5. `aws s3api get-bucket-logging --bucket <name>` (authorized)

## Indicators to Record
1. Public access block disabled.
2. Bucket policy allows `Principal: *`.
3. Missing default encryption.
4. Logging disabled on sensitive buckets.

## Evidence Checklist
1. Bucket list with region and tags (if permitted).
2. Public access block status.
3. Policy status summaries.
4. Encryption and logging status evidence.
