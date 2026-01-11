"""
NeuroSploit SaaS v2 - Scheduler Service
Handles cron-like scheduling for continuous scanning
"""

import logging
from datetime import datetime, timedelta
from typing import Optional
from croniter import croniter
import pytz

logger = logging.getLogger(__name__)

class SchedulerService:
    """Service for calculating next run times from cron expressions"""
    
    @staticmethod
    def parse_cron(cron_expression: str, timezone: str = "UTC") -> bool:
        """Validate cron expression"""
        try:
            croniter(cron_expression)
            return True
        except Exception as e:
            logger.error(f"Invalid cron expression '{cron_expression}': {e}")
            return False
    
    @staticmethod
    def calculate_next_run(
        cron_expression: str,
        base_time: Optional[datetime] = None,
        timezone: str = "UTC"
    ) -> datetime:
        """
        Calculate next run time from cron expression
        
        Args:
            cron_expression: Cron expression (e.g., "0 2 * * *")
            base_time: Base time to calculate from (default: now)
            timezone: Timezone for calculation (default: UTC)
        
        Returns:
            Next run datetime in UTC
        """
        try:
            tz = pytz.timezone(timezone)
            
            if base_time is None:
                base_time = datetime.now(tz)
            elif base_time.tzinfo is None:
                base_time = tz.localize(base_time)
            
            cron = croniter(cron_expression, base_time)
            next_run = cron.get_next(datetime)
            
            # Convert to UTC
            if next_run.tzinfo is None:
                next_run = tz.localize(next_run)
            next_run_utc = next_run.astimezone(pytz.UTC)
            
            return next_run_utc.replace(tzinfo=None)
            
        except Exception as e:
            logger.error(f"Failed to calculate next run: {e}")
            raise
    
    @staticmethod
    def get_schedule_description(cron_expression: str) -> str:
        """
        Get human-readable description of cron schedule
        
        Examples:
            "0 2 * * *" -> "Daily at 2:00 AM"
            "*/15 * * * *" -> "Every 15 minutes"
            "0 0 * * 0" -> "Weekly on Sunday at midnight"
        """
        try:
            parts = cron_expression.split()
            if len(parts) != 5:
                return "Custom schedule"
            
            minute, hour, day, month, weekday = parts
            
            # Every X minutes
            if minute.startswith("*/"):
                interval = minute[2:]
                return f"Every {interval} minutes"
            
            # Hourly
            if hour == "*" and minute != "*":
                return f"Hourly at :{minute.zfill(2)}"
            
            # Daily
            if day == "*" and month == "*" and weekday == "*":
                return f"Daily at {hour.zfill(2)}:{minute.zfill(2)}"
            
            # Weekly
            if weekday != "*" and day == "*" and month == "*":
                days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
                day_name = days[int(weekday)] if weekday.isdigit() else "specified day"
                return f"Weekly on {day_name} at {hour.zfill(2)}:{minute.zfill(2)}"
            
            # Monthly
            if day != "*" and month == "*" and weekday == "*":
                return f"Monthly on day {day} at {hour.zfill(2)}:{minute.zfill(2)}"
            
            return "Custom schedule"
            
        except Exception:
            return "Custom schedule"

# Common cron patterns
CRON_PATTERNS = {
    "every_15_minutes": "*/15 * * * *",
    "every_30_minutes": "*/30 * * * *",
    "hourly": "0 * * * *",
    "daily_2am": "0 2 * * *",
    "daily_midnight": "0 0 * * *",
    "weekly_sunday": "0 0 * * 0",
    "weekly_monday": "0 0 * * 1",
    "monthly_1st": "0 0 1 * *",
}
