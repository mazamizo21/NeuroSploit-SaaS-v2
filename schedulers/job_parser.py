"""
TazoSploit Job Parser
Natural language parsing for job schedules and descriptions
"""

import re
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
from dateutil import parser as dateutil_parser
from parsedatetime import Calendar

from .job_types import JobType


class JobParser:
    """
    Parse natural language job schedules and descriptions
    
    Examples:
        - "in 2 hours"
        - "daily at 3am"
        - "every 30 minutes"
        - "next monday at 9am"
        - "every weekday at 10am"
    """
    
    def __init__(self):
        self.cal = Calendar()
    
    def parse_schedule(self, natural_schedule: str, base_time: Optional[datetime] = None) -> Tuple[datetime, str]:
        """
        Parse natural language schedule to datetime and cron expression
        
        Args:
            natural_schedule: Natural language schedule (e.g., "in 2 hours", "daily at 3am")
            base_time: Base time for relative scheduling (default: now)
        
        Returns:
            Tuple of (scheduled_datetime, cron_expression_or_none)
        """
        if base_time is None:
            base_time = datetime.utcnow()
        
        # Try relative time expressions first
        if natural_schedule.lower().startswith("in "):
            return self._parse_relative_time(natural_schedule, base_time)
        
        # Try recurring schedules
        if natural_schedule.lower().startswith("every "):
            return self._parse_recurring(natural_schedule, base_time)
        
        # Try daily/weekly/monthly schedules
        if "daily at" in natural_schedule.lower():
            return self._parse_daily_schedule(natural_schedule, base_time)
        
        if "weekly on" in natural_schedule.lower() or "weekly at" in natural_schedule.lower():
            return self._parse_weekly_schedule(natural_schedule, base_time)
        
        if "monthly on" in natural_schedule.lower():
            return self._parse_monthly_schedule(natural_schedule, base_time)
        
        # Try parsedatetime as fallback
        return self._parse_with_calendar(natural_schedule, base_time)
    
    def _parse_relative_time(self, schedule: str, base_time: datetime) -> Tuple[datetime, None]:
        """Parse relative time like 'in 2 hours'"""
        match = re.match(r'^in\s+(\d+)\s+(second|minute|hour|day|week)s?', schedule.lower())
        if not match:
            raise ValueError(f"Could not parse relative time: {schedule}")
        
        amount = int(match.group(1))
        unit = match.group(2)
        
        delta_map = {
            'second': timedelta(seconds=1),
            'minute': timedelta(minutes=1),
            'hour': timedelta(hours=1),
            'day': timedelta(days=1),
            'week': timedelta(weeks=1)
        }
        
        delta = delta_map[unit] * amount
        return (base_time + delta, None)
    
    def _parse_recurring(self, schedule: str, base_time: datetime) -> Tuple[datetime, str]:
        """Parse recurring schedule like 'every 30 minutes'"""
        # Every X minutes
        match = re.match(r'^every\s+(\d+)\s+minutes?$', schedule.lower())
        if match:
            minutes = int(match.group(1))
            cron = f"*/{minutes} * * * *"
            next_run = self._cron_to_next(cron, base_time)
            return (next_run, cron)
        
        # Every X hours
        match = re.match(r'^every\s+(\d+)\s+hours?$', schedule.lower())
        if match:
            hours = int(match.group(1))
            cron = f"0 */{hours} * * *"
            next_run = self._cron_to_next(cron, base_time)
            return (next_run, cron)
        
        # Every day at X
        match = re.match(r'^every\s+day\s+at\s+(\d{1,2}):?(\d{2})\s*(am|pm)?$', schedule.lower())
        if match:
            hour = int(match.group(1))
            minute = int(match.group(2))
            period = match.group(3)
            
            if period == 'pm' and hour < 12:
                hour += 12
            elif period == 'am' and hour == 12:
                hour = 0
            
            cron = f"{minute} {hour} * * *"
            next_run = self._cron_to_next(cron, base_time)
            return (next_run, cron)
        
        # Every weekday at X
        match = re.match(r'^every\s+weekday\s+at\s+(\d{1,2}):?(\d{2})\s*(am|pm)?$', schedule.lower())
        if match:
            hour = int(match.group(1))
            minute = int(match.group(2))
            period = match.group(3)
            
            if period == 'pm' and hour < 12:
                hour += 12
            elif period == 'am' and hour == 12:
                hour = 0
            
            cron = f"{minute} {hour} * * 1-5"
            next_run = self._cron_to_next(cron, base_time)
            return (next_run, cron)
        
        raise ValueError(f"Could not parse recurring schedule: {schedule}")
    
    def _parse_daily_schedule(self, schedule: str, base_time: datetime) -> Tuple[datetime, str]:
        """Parse 'daily at 3am' pattern"""
        match = re.match(r'^daily\s+at\s+(\d{1,2}):?(\d{2})\s*(am|pm)?$', schedule.lower())
        if not match:
            raise ValueError(f"Could not parse daily schedule: {schedule}")
        
        hour = int(match.group(1))
        minute = int(match.group(2))
        period = match.group(3)
        
        if period == 'pm' and hour < 12:
            hour += 12
        elif period == 'am' and hour == 12:
            hour = 0
        
        cron = f"{minute} {hour} * * *"
        next_run = self._cron_to_next(cron, base_time)
        return (next_run, cron)
    
    def _parse_weekly_schedule(self, schedule: str, base_time: datetime) -> Tuple[datetime, str]:
        """Parse 'weekly on Monday at 9am' pattern"""
        # Day mapping
        days = {
            'monday': 1, 'tuesday': 2, 'wednesday': 3, 'thursday': 4,
            'friday': 5, 'saturday': 6, 'sunday': 0
        }
        
        match = re.match(r'^weekly\s+(?:on\s+(\w+)|(?:at\s+(\d{1,2}):?(\d{2})\s*(am|pm)?)?)', schedule.lower())
        if not match:
            raise ValueError(f"Could not parse weekly schedule: {schedule}")
        
        day_name = match.group(1)
        hour = match.group(2)
        minute = match.group(3)
        period = match.group(4)
        
        # Parse day
        if day_name:
            day_num = days.get(day_name.lower())
            if day_num is None:
                raise ValueError(f"Invalid day: {day_name}")
        else:
            day_num = 0  # Default to Sunday
        
        # Parse time
        if hour:
            hour_num = int(hour)
            minute_num = int(minute) if minute else 0
            
            if period == 'pm' and hour_num < 12:
                hour_num += 12
            elif period == 'am' and hour_num == 12:
                hour_num = 0
        else:
            hour_num = 0
            minute_num = 0
        
        cron = f"{minute_num} {hour_num} * * {day_num}"
        next_run = self._cron_to_next(cron, base_time)
        return (next_run, cron)
    
    def _parse_monthly_schedule(self, schedule: str, base_time: datetime) -> Tuple[datetime, str]:
        """Parse 'monthly on the 15th at 10am' pattern"""
        match = re.match(r'^monthly\s+on\s+(?:the\s+)?(\d{1,2})(?:st|nd|rd|th)?\s+at\s+(\d{1,2}):?(\d{2})\s*(am|pm)?$', schedule.lower())
        if not match:
            raise ValueError(f"Could not parse monthly schedule: {schedule}")
        
        day = int(match.group(1))
        hour = int(match.group(2))
        minute = int(match.group(3))
        period = match.group(4)
        
        if day < 1 or day > 31:
            raise ValueError(f"Invalid day of month: {day}")
        
        if period == 'pm' and hour < 12:
            hour += 12
        elif period == 'am' and hour == 12:
            hour = 0
        
        cron = f"{minute} {hour} {day} * *"
        next_run = self._cron_to_next(cron, base_time)
        return (next_run, cron)
    
    def _parse_with_calendar(self, schedule: str, base_time: datetime) -> Tuple[datetime, None]:
        """Use parsedatetime as fallback"""
        parse_result, confidence = self.cal.parse(schedule, sourceTime=base_time)
        
        if confidence > 0:
            scheduled_time = datetime.fromtimestamp(parse_result)
            return (scheduled_time, None)
        
        raise ValueError(f"Could not parse schedule: {schedule}")
    
    def _cron_to_next(self, cron: str, base_time: datetime) -> datetime:
        """Calculate next run time from cron expression"""
        from croniter import croniter
        
        try:
            cron_obj = croniter(cron, base_time)
            return cron_obj.get_next(datetime)
        except Exception as e:
            raise ValueError(f"Invalid cron expression '{cron}': {e}")
    
    def extract_job_params(self, description: str) -> Dict[str, Any]:
        """
        Extract job parameters from natural language description
        
        Examples:
            "scan target.com with nmap" -> {'type': 'scan', 'target': 'target.com', 'tools': ['nmap']}
            "check for new CVEs every 6 hours" -> {'type': 'recon', 'check': 'cves'}
        """
        params = {}
        description_lower = description.lower()
        
        # Extract target (domains, IPs)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b'
        
        ips = re.findall(ip_pattern, description)
        domains = re.findall(domain_pattern, description)
        
        if ips:
            params['targets'] = ips
        if domains:
            params['domains'] = domains
        
        # Extract job type
        if 'scan' in description_lower:
            params['job_type'] = 'scan'
        elif 'recon' in description_lower or 'discover' in description_lower:
            params['job_type'] = 'recon'
        elif 'exploit' in description_lower:
            params['job_type'] = 'exploit'
        elif 'report' in description_lower or 'generate' in description_lower:
            params['job_type'] = 'report'
        elif 'monitor' in description_lower:
            params['job_type'] = 'monitor'
        elif 'cleanup' in description_lower or 'clean' in description_lower:
            params['job_type'] = 'cleanup'
        elif 'cve' in description_lower:
            params['job_type'] = 'recon'
            params['check'] = 'cves'
        
        # Extract tools mentioned
        tools = []
        if 'nmap' in description_lower:
            tools.append('nmap')
        if 'nuclei' in description_lower:
            tools.append('nuclei')
        if 'subfinder' in description_lower:
            tools.append('subfinder')
        if 'amass' in description_lower:
            tools.append('amass')
        if 'metasploit' in description_lower:
            tools.append('metasploit')
        
        if tools:
            params['tools'] = tools
        
        # Extract scan type
        if 'quick' in description_lower:
            params['scan_type'] = 'quick'
        elif 'full' in description_lower or 'comprehensive' in description_lower:
            params['scan_type'] = 'full'
        elif 'stealth' in description_lower or 'quiet' in description_lower:
            params['scan_type'] = 'stealth'
        elif 'aggressive' in description_lower:
            params['scan_type'] = 'aggressive'
        
        return params


# Predefined job templates for common tasks
JOB_TEMPLATES = {
    "quick_scan": {
        "job_type": JobType.SCAN,
        "name": "Quick Security Scan",
        "description": "Quick port scan and vulnerability check",
        "scan_type": "quick",
        "tools": ["nmap"],
        "timeout": 1800
    },
    "full_scan": {
        "job_type": JobType.SCAN,
        "name": "Full Security Scan",
        "description": "Comprehensive security scan with multiple tools",
        "scan_type": "full",
        "tools": ["nmap", "nuclei"],
        "timeout": 7200
    },
    "subdomain_recon": {
        "job_type": JobType.RECON,
        "name": "Subdomain Discovery",
        "description": "Discover all subdomains for a target",
        "recon_type": "subdomain",
        "tools": ["subfinder", "amass"],
        "passive_only": True
    },
    "daily_monitor": {
        "job_type": JobType.MONITOR,
        "name": "Daily Availability Monitor",
        "description": "Monitor target availability daily",
        "monitor_type": "availability",
        "check_interval": 86400
    },
    "cleanup_logs": {
        "job_type": JobType.CLEANUP,
        "name": "Log Cleanup",
        "description": "Clean up old log files",
        "cleanup_type": "logs",
        "older_than_days": 30
    }
}
