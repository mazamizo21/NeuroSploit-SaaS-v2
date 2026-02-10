# Security Controls and Policies

## Goals
1. Identify policy controls in use (NetworkPolicy, Pod Security).
2. Capture admission controllers or policy engines.
3. Record audit or policy enforcement modes.

## Safe Checks
1. `kubectl get networkpolicies -A -o json`
2. `kubectl get podsecuritypolicies` (if enabled)
3. `kubectl get validatingwebhookconfigurations`
4. `kubectl get mutatingwebhookconfigurations`

## Indicators to Record
1. No NetworkPolicies in sensitive namespaces.
2. Pod security controls disabled.
3. Admission policies not enforcing deny-by-default.

## Evidence Checklist
1. Policy object counts.
2. Notes on missing controls.
3. Webhook configuration summaries.
