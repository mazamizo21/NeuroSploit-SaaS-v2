# SSRF Testing Examples

## Example 1: Basic SSRF Detection
**Scenario:** Web application with URL fetch feature at `/api/preview?url=`
1. Test with external collaborator URL → callback received
2. Test with `http://127.0.0.1/` → different response than invalid URL
3. Confirm full SSRF — response body visible

## Example 2: AWS Metadata Extraction
**Scenario:** Full SSRF on cloud-hosted application
1. Fetch `http://169.254.169.254/latest/meta-data/` → directory listing
2. Discover IAM role at `iam/security-credentials/`
3. Extract temporary credentials (AccessKeyId, SecretAccessKey, Token)
4. Document finding with redacted credentials

## Example 3: Filter Bypass via DNS
**Scenario:** Application blocks `127.0.0.1` and `169.254.169.254`
1. Try `http://127.0.0.1.nip.io/` → bypasses IP blocklist
2. Try decimal `http://2130706433/` → bypasses string matching
3. Try redirect from external server → bypasses initial URL check
