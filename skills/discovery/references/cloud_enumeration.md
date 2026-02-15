# Cloud Instance Enumeration Reference

## Detection: Am I in the Cloud?

```bash
# Quick cloud detection
curl -s --connect-timeout 2 http://169.254.169.254/ >/dev/null 2>&1 && echo "Metadata service reachable (likely cloud)"

# Check for cloud-specific tools
which aws 2>/dev/null && echo "AWS CLI installed"
which az 2>/dev/null && echo "Azure CLI installed"
which gcloud 2>/dev/null && echo "Google Cloud CLI installed"

# Check DMI/BIOS for cloud vendor
cat /sys/class/dmi/id/bios_vendor 2>/dev/null     # Amazon, Google, Microsoft
cat /sys/class/dmi/id/product_name 2>/dev/null    # "Virtual Machine" etc.
cat /sys/class/dmi/id/sys_vendor 2>/dev/null
dmidecode -s system-manufacturer 2>/dev/null       # Requires root

# Check for cloud-init
cat /run/cloud-init/result.json 2>/dev/null
cat /var/log/cloud-init.log 2>/dev/null | head -20
ls /var/lib/cloud/ 2>/dev/null
```

---

## AWS EC2 Enumeration

### Instance Metadata Service (IMDS)

#### IMDSv1 (No Token Required)
```bash
# Instance identity
curl -s http://169.254.169.254/latest/meta-data/instance-id
curl -s http://169.254.169.254/latest/meta-data/instance-type
curl -s http://169.254.169.254/latest/meta-data/ami-id
curl -s http://169.254.169.254/latest/meta-data/hostname
curl -s http://169.254.169.254/latest/meta-data/local-hostname
curl -s http://169.254.169.254/latest/meta-data/local-ipv4
curl -s http://169.254.169.254/latest/meta-data/public-ipv4
curl -s http://169.254.169.254/latest/meta-data/public-hostname
curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone
curl -s http://169.254.169.254/latest/meta-data/placement/region

# Security groups and networking
curl -s http://169.254.169.254/latest/meta-data/security-groups
curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/
curl -s http://169.254.169.254/latest/meta-data/mac
MAC=$(curl -s http://169.254.169.254/latest/meta-data/mac)
curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/vpc-id
curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/subnet-id
curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/security-group-ids

# IAM role credentials (CRITICAL — may grant cloud access)
curl -s http://169.254.169.254/latest/meta-data/iam/info
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE

# User data (may contain secrets, scripts, bootstrap configs)
curl -s http://169.254.169.254/latest/user-data/

# Instance identity document
curl -s http://169.254.169.254/latest/dynamic/instance-identity/document
```

#### IMDSv2 (Token Required)
```bash
# Get session token first
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Then use token in subsequent requests
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/user-data/
```

### AWS CLI Enumeration (If Installed)
```bash
# Identity
aws sts get-caller-identity              # Who am I?
aws sts get-session-token                # Current session

# IAM
aws iam list-users                       # All IAM users
aws iam list-roles                       # All IAM roles
aws iam list-policies --only-attached    # Attached policies
aws iam get-user                         # Current user details
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>
aws iam get-policy-version --policy-arn <arn> --version-id <v>

# S3
aws s3 ls                               # List buckets
aws s3 ls s3://<bucket> --recursive     # List bucket contents

# EC2
aws ec2 describe-instances --region <region>
aws ec2 describe-security-groups --region <region>
aws ec2 describe-vpcs --region <region>
aws ec2 describe-subnets --region <region>

# Secrets Manager / SSM
aws secretsmanager list-secrets
aws ssm describe-parameters
aws ssm get-parameters-by-path --path "/" --recursive

# Lambda
aws lambda list-functions --region <region>
aws lambda get-function --function-name <name>
```

---

## Azure Enumeration

### Instance Metadata Service (IMDS)
```bash
# Instance info
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | python3 -m json.tool

# Specific fields
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance/compute/name?api-version=2021-02-01&format=text"
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2021-02-01&format=text"
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance/compute/subscriptionId?api-version=2021-02-01&format=text"
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01&format=text"
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text"
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance/compute/osType?api-version=2021-02-01&format=text"

# Network info
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01" | python3 -m json.tool

# Managed Identity access token (CRITICAL)
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com"

# Scheduled events
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/scheduledevents?api-version=2020-07-01"
```

### Azure CLI Enumeration (If Installed)
```bash
# Identity
az account show                          # Current subscription
az account list                          # All subscriptions
az ad signed-in-user show               # Current user

# Resources
az vm list                               # VMs
az storage account list                  # Storage accounts
az keyvault list                         # Key vaults
az keyvault secret list --vault-name <name>  # Vault secrets
az keyvault secret show --vault-name <name> --name <secret>

# AD
az ad user list                          # Azure AD users
az ad group list                         # Azure AD groups
az ad sp list --all                      # Service principals
az role assignment list --all            # Role assignments

# Network
az network vnet list                     # Virtual networks
az network nsg list                      # Network security groups
```

---

## GCP Enumeration

### Metadata Server
```bash
# Instance info
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true" | python3 -m json.tool

# Specific fields
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/hostname"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/zone"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/machine-type"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/name"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/tags"

# Project info
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/project-id"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/attributes/?recursive=true"

# Service account info and access tokens (CRITICAL)
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"

# Custom metadata (may contain secrets)
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script"

# Kubernetes (if on GKE)
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env"
```

### GCP CLI Enumeration (If Installed)
```bash
# Identity
gcloud auth list                         # Authenticated accounts
gcloud config list                       # Current config
gcloud info                              # Full SDK info

# Projects and compute
gcloud projects list                     # All projects
gcloud compute instances list            # VMs
gcloud compute networks list             # Networks
gcloud compute firewall-rules list       # Firewall rules

# IAM
gcloud iam service-accounts list         # Service accounts
gcloud projects get-iam-policy <project-id>  # IAM policies

# Storage
gcloud storage ls                        # GCS buckets
gcloud storage ls gs://<bucket>         # Bucket contents

# Secrets
gcloud secrets list                      # Secret Manager secrets
gcloud secrets versions access latest --secret=<name>  # Read secret
```

---

## Credential File Locations (All Clouds)

```bash
# AWS
~/.aws/credentials                       # Access keys
~/.aws/config                            # Region, profile config
/root/.aws/credentials                   # Root user's AWS creds

# Azure
~/.azure/accessTokens.json              # Azure auth tokens
~/.azure/azureProfile.json              # Azure profile

# GCP
~/.config/gcloud/credentials.db          # GCP credentials
~/.config/gcloud/application_default_credentials.json
~/.config/gcloud/access_tokens.db
/etc/boto.cfg                            # GCS boto config
~/.boto                                  # User boto config

# Kubernetes
~/.kube/config                           # Kubeconfig
/var/run/secrets/kubernetes.io/serviceaccount/token  # K8s service account token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

---

## Post-Token Actions

Once you have a cloud access token or credentials:
1. **Identify permissions** — what can this identity do?
2. **Enumerate resources** — storage, VMs, databases, secrets
3. **Check for lateral movement** — other instances, cross-account roles
4. **Look for stored secrets** — Secrets Manager, Key Vault, Secret Manager
5. **Check for overprivileged roles** — admin/owner/contributor
