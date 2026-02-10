"""
TazoSploit Job Type Definitions
Structured job configurations for different pentest task types
"""

from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass, field
import json


class JobType(str, Enum):
    """Enumeration of supported job types"""
    SCAN = "scan_jobs"
    RECON = "recon_jobs"
    EXPLOIT = "exploit_jobs"
    REPORT = "report_jobs"
    MONITOR = "monitor_jobs"
    CLEANUP = "cleanup_jobs"


class JobStatus(str, Enum):
    """Job lifecycle states"""
    SCHEDULED = "scheduled"
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobPriority(str, Enum):
    """Priority levels for job execution"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BaseJobConfig:
    """Base configuration for all job types"""
    name: str
    job_type: JobType
    description: Optional[str] = None
    priority: JobPriority = JobPriority.NORMAL
    timeout: int = 3600  # Default 1 hour timeout
    retry_on_failure: bool = True
    max_retries: int = 3
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanJob(BaseJobConfig):
    """Configuration for scan jobs (Nmap, Nuclei, etc.)"""
    job_type: JobType = JobType.SCAN
    target: str = ""
    scan_type: str = "full"  # quick, full, stealth, aggressive
    tools: List[str] = field(default_factory=lambda: ["nmap", "nuclei"])
    ports: str = "1-65535"
    custom_options: Dict[str, Any] = field(default_factory=dict)
    output_format: str = "json"  # json, xml, txt
    save_results: bool = True
    
    def __post_init__(self):
        if not self.target:
            raise ValueError("ScanJob requires a target")


@dataclass
class ReconJob(BaseJobConfig):
    """Configuration for reconnaissance jobs"""
    job_type: JobType = JobType.RECON
    target: str = ""
    recon_type: str = "subdomain"  # subdomain, asset, dns, technology
    tools: List[str] = field(default_factory=lambda: ["subfinder", "amass"])
    passive_only: bool = True
    depth: int = 3
    save_results: bool = True
    
    def __post_init__(self):
        if not self.target:
            raise ValueError("ReconJob requires a target")


@dataclass
class ExploitJob(BaseJobConfig):
    """Configuration for exploitation jobs"""
    job_type: JobType = JobType.EXPLOIT
    target: str = ""
    exploit_type: str = "automatic"  # automatic, manual, metasploit, custom
    cve_ids: List[str] = field(default_factory=list)
    payload_type: Optional[str] = None
    exploit_chain: List[str] = field(default_factory=list)
    safe_mode: bool = True  # Verify before exploit
    max_harm: str = "minimal"  # minimal, moderate, significant
    
    def __post_init__(self):
        if not self.target:
            raise ValueError("ExploitJob requires a target")
        if self.max_harm not in ["minimal", "moderate", "significant"]:
            raise ValueError(f"Invalid max_harm: {self.max_harm}")


@dataclass
class ReportJob(BaseJobConfig):
    """Configuration for report generation jobs"""
    job_type: JobType = JobType.REPORT
    report_type: str = "full"  # full, executive, technical, custom
    target_pentest_id: Optional[str] = None
    include_sections: List[str] = field(default_factory=lambda: [
        "executive_summary", "findings", "risk_assessment", "remediation"
    ])
    output_format: str = "pdf"  # pdf, html, markdown, json
    template: Optional[str] = None
    branding: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MonitorJob(BaseJobConfig):
    """Configuration for continuous monitoring jobs"""
    job_type: JobType = JobType.MONITOR
    target: str = ""
    monitor_type: str = "availability"  # availability, vuln_scan, reputation
    check_interval: int = 300  # seconds
    notification_on_change: bool = True
    alert_channels: List[str] = field(default_factory=list)
    thresholds: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.target:
            raise ValueError("MonitorJob requires a target")


@dataclass
class CleanupJob(BaseJobConfig):
    """Configuration for cleanup jobs"""
    job_type: JobType = JobType.CLEANUP
    cleanup_type: str = "logs"  # logs, temp_files, old_reports, all
    older_than_days: int = 30
    path_patterns: List[str] = field(default_factory=list)
    dry_run: bool = False  # Preview without deleting


@dataclass
class Job:
    """Complete job definition with execution metadata"""
    id: str
    config: BaseJobConfig
    status: JobStatus = JobStatus.SCHEDULED
    created_at: datetime = field(default_factory=datetime.utcnow)
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    retry_count: int = 0
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    logs: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert job to dictionary for persistence"""
        return {
            'id': self.id,
            'job_type': self.config.job_type.value,
            'name': self.config.name,
            'description': self.config.description,
            'priority': self.config.priority.value,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'scheduled_at': self.scheduled_at.isoformat() if self.scheduled_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'retry_count': self.retry_count,
            'config': self._serialize_config(),
            'result': self.result,
            'error_message': self.error_message,
            'logs': self.logs
        }
    
    def _serialize_config(self) -> Dict[str, Any]:
        """Serialize job config to dict"""
        if isinstance(self.config, dataclass):
            config_dict = {
                'job_type': self.config.job_type.value,
                'name': self.config.name,
                'description': self.config.description,
                'priority': self.config.priority.value,
                'timeout': self.config.timeout,
                'retry_on_failure': self.config.retry_on_failure,
                'max_retries': self.config.max_retries,
                'tags': self.config.tags,
                'metadata': self.config.metadata
            }
            
            # Add type-specific fields
            config_dict.update({
                k: v for k, v in self.config.__dict__.items()
                if k not in config_dict and not k.startswith('_')
            })
            
            return config_dict
        return {}
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Job':
        """Create Job instance from dictionary"""
        config_data = data.get('config', {})
        job_type_str = config_data.get('job_type', JobType.SCAN.value)
        
        # Get appropriate job class
        job_class = {
            JobType.SCAN.value: ScanJob,
            JobType.RECON.value: ReconJob,
            JobType.EXPLOIT.value: ExploitJob,
            JobType.REPORT.value: ReportJob,
            JobType.MONITOR.value: MonitorJob,
            JobType.CLEANUP.value: CleanupJob
        }.get(job_type_str, ScanJob)
        
        # Create config
        config = job_class(**{k: v for k, v in config_data.items() if k in job_class.__annotations__})
        
        # Create job
        return cls(
            id=data['id'],
            config=config,
            status=JobStatus(data.get('status', JobStatus.SCHEDULED.value)),
            created_at=datetime.fromisoformat(data['created_at']),
            scheduled_at=datetime.fromisoformat(data['scheduled_at']) if data.get('scheduled_at') else None,
            started_at=datetime.fromisoformat(data['started_at']) if data.get('started_at') else None,
            completed_at=datetime.fromisoformat(data['completed_at']) if data.get('completed_at') else None,
            retry_count=data.get('retry_count', 0),
            result=data.get('result'),
            error_message=data.get('error_message'),
            logs=data.get('logs', [])
        )
    
    def add_log(self, message: str):
        """Add a log entry to the job"""
        timestamp = datetime.utcnow().isoformat()
        self.logs.append(f"[{timestamp}] {message}")
    
    def get_duration(self) -> Optional[float]:
        """Calculate job duration in seconds"""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


# Job type factory
def create_job_from_template(job_type: JobType, **kwargs) -> BaseJobConfig:
    """Factory function to create job configs"""
    job_classes = {
        JobType.SCAN: ScanJob,
        JobType.RECON: ReconJob,
        JobType.EXPLOIT: ExploitJob,
        JobType.REPORT: ReportJob,
        JobType.MONITOR: MonitorJob,
        JobType.CLEANUP: CleanupJob
    }
    
    job_class = job_classes.get(job_type, ScanJob)
    return job_class(**kwargs)
