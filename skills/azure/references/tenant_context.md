# Azure Tenant and Subscription Context

## Goals
1. Confirm tenant ID and active subscriptions.
2. Record region scope and active account context.
3. Capture principal type and tenant domain details.

## Safe Checks
1. `az account show`
2. `az account list`
3. `az account tenant list` (if allowed)
4. `az ad signed-in-user show` (if allowed)

## Evidence Checklist
1. Tenant ID and subscription ID.
2. Subscription count and names.
3. Active account UPN/SPN.
4. Tenant domains if available.
