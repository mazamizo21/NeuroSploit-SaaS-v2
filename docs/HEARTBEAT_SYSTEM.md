# Heartbeat System Documentation

## Overview

The TazoSploit Heartbeat System provides continuous proactive monitoring for security issues, threat intelligence, and system health. It runs scheduled checks and generates alerts for discovered issues.

## Architecture

```
heartbeat.py
├── HeartbeatConfig          # Configuration for monitoring
├── HeartbeatSystem          # Core monitoring engine
├── Alert                   # Security alert data structure
├── ServiceInfo             # Discovered service information
└── generate_cron_config()  # Crontab generator
```

## Core Components

### HeartbeatConfig

Configuration object for heartbeat monitoring:

```python
from heartbeat import HeartbeatConfig

config = HeartbeatConfig()
config.check_interval_minutes = 60
config.cve_check_interval_hours = 24
config.daily_summary_time = "08:00"
config.scan_networks = ["192.168.1.0/24"]
config.notification_channels = ["slack", "email", "log"]
config.slack_webhook_url = "https://hooks.slack.com/..."
config.smtp_server = "smtp.example.com"
config.smtp_port = 587
config.smtp_username = "alerts@example.com"
config.smtp_password = "password"
config.smtp_from = "alerts@example.com"
config.smtp_to = ["security@example.com"]
config.log_file = "/pentest/logs/heartbeat.log"
```

### HeartbeatSystem

Main monitoring system:

```python
from heartbeat import HeartbeatSystem

system = HeartbeatSystem(config=config, memory_store=memory_store)

# Start monitoring loop
await system.start()

# Stop monitoring
system.stop()
```

## Monitoring Checks

### 1. New Service Discovery

Automatically discovers new services on monitored networks:

```python
# Networks to scan
config.scan_networks = ["192.168.1.0/24", "10.0.0.0/8"]

# When a new service is discovered:
# 1. Alert is generated
# 2. Service is added to known services
# 3. Recommendations are provided
```

### 2. CVE Checks

Checks for known vulnerabilities in discovered tech stack:

```python
# Check interval
config.cve_check_interval_hours = 24

# When CVEs are found:
# 1. Alert generated with CVE details
# 2. Affected systems listed
# 3. Recommendations provided
```

### 3. Credential Reuse Detection

Identifies credentials reused across multiple targets:

```python
# Analyzes memory store for credential patterns
# Detects:
# - Same credentials on multiple systems
# - Weak password patterns
# - Default credentials

# When reuse detected:
# 1. High/Medium severity alert generated
# 2. List of affected targets provided
# 3. Remediation recommendations provided
```

### 4. Daily Threat Summary

Generates comprehensive daily summary at configured time:

```python
config.daily_summary_time = "08:00"

# Summary includes:
# - Total alerts (24h)
# - Alerts by category
# - Critical/high alerts
# - Threat patterns
# - Recommendations
```

## Alert Levels

```
CRITICAL - Immediate attention required (critical vulnerabilities, root access)
HIGH      - Important issues requiring attention soon (vulnerabilities, data exposure)
MEDIUM    - Moderate issues (configurations, potential issues)
LOW        - Minor issues (informational findings)
INFO       - General information (new services, summaries)
```

## Alert Categories

- `service_discovery`: New services discovered
- `cve`: Known vulnerabilities detected
- `credential_reuse`: Credentials reused across systems
- `daily_summary`: Daily threat intelligence summary
- `pattern_detection`: Threat patterns identified

## Notification Channels

### 1. Slack

Send alerts to Slack via webhook:

```python
config.notification_channels = ["slack"]
config.slack_webhook_url = "https://hooks.slack.com/services/..."

# Alert format:
# [CRITICAL] Title
# Description
# - Category: category
# - Target: target
# - Time: timestamp
```

### 2. Email

Send alerts via email:

```python
config.notification_channels = ["email"]
config.smtp_server = "smtp.example.com"
config.smtp_port = 587
config.smtp_username = "alerts@example.com"
config.smtp_password = "password"
config.smtp_from = "alerts@example.com"
config.smtp_to = ["security@example.com", "admin@example.com"]
```

### 3. Log

Write alerts to log file:

```python
config.notification_channels = ["log"]
config.log_file = "/pentest/logs/heartbeat.log"
```

## Cron Integration

Generate crontab configuration:

```bash
# Generate cron configuration
python3 heartbeat.py --cron > /tmp/tazosploit_crontab

# Install cron
crontab /tmp/tazosploit_crontab
```

Example cron output:

```cron
# TazoSploit Heartbeat Monitoring
# Run heartbeat checks every 60 minutes
*/60 * * * * cd /pentest && python3 heartbeat.py >> /pentest/logs/heartbeat.log 2>&1

# Daily threat summary at 08:00
0 8 * * * cd /pentest && python3 -c '...' >> /pentest/logs/heartbeat.log 2>&1

# CVE check every 24 hours
0 */24 * * * cd /pentest && python3 -c '...' >> /pentest/logs/heartbeat.log 2>&1
```

## API Reference

### HeartbeatSystem

```python
class HeartbeatSystem:
    def __init__(self, config: HeartbeatConfig = None, 
                 memory_store: EnhancedMemoryStore = None)
    async def start(self)
    def stop(self)
    async def _run_checks(self)
    async def _check_new_services(self)
    async def _check_cves(self)
    async def _check_credential_reuse(self)
    async def _generate_daily_summary(self)
    def _send_alert(self, alert: Alert)
    def get_recent_alerts(self, hours: int = 24) -> List[Alert]
    def get_alerts_by_level(self, level: AlertLevel) -> List[Alert]
    def get_alerts_by_category(self, category: str) -> List[Alert]
```

### Alert

```python
@dataclass
class Alert:
    alert_id: str
    level: AlertLevel
    category: str
    title: str
    description: str
    target: str
    timestamp: str
    evidence: List[str]
    recommendations: List[str]
    metadata: Dict[str, Any]
```

## Examples

### Example 1: Basic Heartbeat Setup

```python
import asyncio
from heartbeat import HeartbeatSystem, HeartbeatConfig

async def main():
    # Configure heartbeat
    config = HeartbeatConfig()
    config.check_interval_minutes = 30
    config.scan_networks = ["192.168.1.0/24"]
    config.notification_channels = ["log"]
    config.log_file = "/pentest/logs/heartbeat.log"
    
    # Start heartbeat
    system = HeartbeatSystem(config)
    await system.start()

asyncio.run(main())
```

### Example 2: Heartbeat with Slack Alerts

```python
config = HeartbeatConfig()
config.check_interval_minutes = 60
config.scan_networks = ["10.0.0.0/8"]
config.notification_channels = ["slack", "log"]
config.slack_webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

system = HeartbeatSystem(config)
await system.start()
```

### Example 3: Querying Alerts

```python
system = HeartbeatSystem()

# Get recent alerts
recent = system.get_recent_alerts(hours=24)
print(f"Last 24 hours: {len(recent)} alerts")

# Get critical alerts
critical = system.get_alerts_by_level(AlertLevel.CRITICAL)
print(f"Critical alerts: {len(critical)}")

# Get credential reuse alerts
creds = system.get_alerts_by_category("credential_reuse")
for alert in creds:
    print(f"{alert.title}: {alert.description}")
```

## Best Practices

1. **Configure Appropriate Intervals**: Balance between timely alerts and resource usage.
2. **Use Multiple Channels**: Configure both real-time (Slack) and persistent (email, log) channels.
3. **Review Daily Summaries**: Use daily summaries to track trends and patterns.
4. **Act on Alerts**: Respond to high/critical alerts promptly.
5. **Tune False Positives**: Adjust patterns to reduce false positive alerts.

## Troubleshooting

### Heartbeat Not Starting

**Problem**: Heartbeat fails to start.

**Solution**:
1. Check that `/pentest/logs` directory exists and is writable
2. Verify network ranges are valid CIDR notation
3. Check SMTP/Slack configuration if using notifications
4. Review log file for error messages

### No Alerts Being Generated

**Problem**: Heartbeat runs but no alerts appear.

**Solution**:
1. Verify `scan_networks` is configured and accessible
2. Check that memory_store is being updated
3. Ensure notification channels are properly configured
4. Review heartbeat.log for errors

### CVE Checks Failing

**Problem**: CVE checks return errors.

**Solution**:
1. Verify CVE lookup service is available
2. Check network connectivity to CVE databases
3. Ensure `last_cve_check` is being updated in memory
4. Review service versions are being detected correctly

## Integration with Memory System

Heartbeat integrates with `EnhancedMemoryStore` for pattern detection:

```python
from memory.memory_store import EnhancedMemoryStore
from heartbeat import HeartbeatSystem

memory_store = EnhancedMemoryStore(tenant_id="default", target="global")
system = HeartbeatSystem(config=config, memory_store=memory_store)

# Heartbeat will:
# - Read credential patterns from memory
# - Detect reuse across targets
# - Track threat patterns
# - Update memory with new findings
```

## Security Considerations

1. **Protect Notification Credentials**: Store SMTP/Slack credentials securely.
2. **Limit Network Exposure**: Only scan authorized networks.
3. **Secure Alert Data**: Avoid sending sensitive data in alerts.
4. **Monitor for Abuse**: Ensure heartbeat isn't being abused for reconnaissance.
5. **Rate Limit**: Don't overwhelm notification systems with alerts.

## Future Enhancements

- Machine learning for anomaly detection
- Integration with external threat feeds
- Automated remediation suggestions
- Real-time dashboard
- Alert correlation and grouping
- Integration with SIEM systems
