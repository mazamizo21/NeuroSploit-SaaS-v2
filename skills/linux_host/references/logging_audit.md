# Linux Logging and Audit Coverage

## Checks
1. auditd service status and rules loaded for auth, exec, and privilege events.
2. journald retention and storage settings (`Storage`, `SystemMaxUse`, `RuntimeMaxUse`).
3. logrotate policies for auth and system logs.
4. rsyslog or syslog-ng forwarding configured if required.
5. Log file permissions and ownership for `/var/log` sensitive files.

## Evidence Capture
1. auditd status and rule summaries.
2. journald and logrotate config excerpts.
3. rsyslog forwarding destinations and log file permission evidence.
