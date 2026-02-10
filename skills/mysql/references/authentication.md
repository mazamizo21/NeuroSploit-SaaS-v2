# MySQL Authentication and TLS

## Goals
1. Identify auth plugins and TLS requirements.
2. Capture server version and handshake metadata.
3. Record password policy and auth plugin posture.

## Safe Checks
1. `nmap --script mysql-info,mysql-variables`
2. `SHOW VARIABLES LIKE 'version%';` (authorized)
3. `SHOW VARIABLES LIKE 'require_secure_transport';`
4. `SHOW VARIABLES LIKE 'default_authentication_plugin';`

## Indicators to Record
1. `mysql_native_password` still enabled on external endpoints.
2. TLS not required on public interfaces.
3. Weak password policy or disabled validation.

## Evidence Checklist
1. Version and auth plugin info.
2. TLS requirement status.
3. Password policy and auth plugin settings.
