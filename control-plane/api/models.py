"""
NeuroSploit SaaS v2 - Database Models
Multi-tenant data model with full audit logging
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, Boolean, Integer, ForeignKey, JSON, Enum
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import enum

from .database import Base

class TenantTier(str, enum.Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"

class JobStatus(str, enum.Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"

class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

# =============================================================================
# TENANT MANAGEMENT
# =============================================================================

class Tenant(Base):
    """Multi-tenant organization"""
    __tablename__ = "tenants"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    tier = Column(Enum(TenantTier), default=TenantTier.FREE)
    
    # Limits based on tier
    max_concurrent_jobs = Column(Integer, default=1)
    max_scopes = Column(Integer, default=5)
    max_monthly_jobs = Column(Integer, default=10)
    
    # Security
    api_key_hash = Column(String(255))
    encryption_key_id = Column(String(255))  # Reference to Vault/KMS
    
    # Verification
    domain_verified = Column(Boolean, default=False)
    payment_verified = Column(Boolean, default=False)
    kyc_verified = Column(Boolean, default=False)
    
    # Metadata
    settings = Column(JSONB, default={})
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    scopes = relationship("Scope", back_populates="tenant", cascade="all, delete-orphan")
    jobs = relationship("Job", back_populates="tenant", cascade="all, delete-orphan")
    policies = relationship("Policy", back_populates="tenant", cascade="all, delete-orphan")

class User(Base):
    """Tenant users"""
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255))
    
    # Profile
    full_name = Column(String(255))
    role = Column(String(50), default="operator")  # admin, operator, viewer, auditor
    
    # Status
    is_active = Column(Boolean, default=True)
    email_verified = Column(Boolean, default=False)
    mfa_enabled = Column(Boolean, default=False)
    
    # Metadata
    last_login = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="users")

# =============================================================================
# SCOPE MANAGEMENT (Target Authorization)
# =============================================================================

class Scope(Base):
    """Approved target scopes for pentesting"""
    __tablename__ = "scopes"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Target definition
    targets = Column(JSONB, nullable=False)  # List of IPs, domains, CIDRs
    excluded_targets = Column(JSONB, default=[])
    
    # Authorization
    authorization_type = Column(String(50))  # self_owned, customer_authorized, bug_bounty
    authorization_proof = Column(Text)  # URL or reference to proof document
    authorization_expires = Column(DateTime)
    
    # Restrictions
    allowed_phases = Column(JSONB, default=["RECON", "VULN_SCAN"])
    max_intensity = Column(String(20), default="medium")
    allowed_hours = Column(JSONB)  # Time windows for testing
    
    # Status
    is_active = Column(Boolean, default=True)
    approved_at = Column(DateTime)
    approved_by = Column(UUID(as_uuid=True))
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="scopes")
    jobs = relationship("Job", back_populates="scope")

# =============================================================================
# JOB MANAGEMENT
# =============================================================================

class Job(Base):
    """Pentest job execution"""
    __tablename__ = "jobs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    scope_id = Column(UUID(as_uuid=True), ForeignKey("scopes.id", ondelete="SET NULL"))
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    
    # Job configuration
    name = Column(String(255), nullable=False)
    description = Column(Text)
    phase = Column(String(50), nullable=False)  # RECON, VULN_SCAN, EXPLOIT, POST_EXPLOIT, REPORT
    
    # Target
    targets = Column(JSONB, nullable=False)
    
    # Execution settings
    intensity = Column(String(20), default="medium")
    timeout_seconds = Column(Integer, default=3600)
    auto_run = Column(Boolean, default=False)
    
    # Status
    status = Column(Enum(JobStatus), default=JobStatus.PENDING)
    progress = Column(Integer, default=0)  # 0-100
    
    # Worker assignment
    worker_id = Column(String(100))
    container_id = Column(String(100))
    
    # Results
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    
    # Cost tracking
    tokens_used = Column(Integer, default=0)
    cost_usd = Column(Integer, default=0)  # Stored as cents
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # Error handling
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="jobs")
    scope = relationship("Scope", back_populates="jobs")
    findings = relationship("Finding", back_populates="job", cascade="all, delete-orphan")
    commands = relationship("CommandLog", back_populates="job", cascade="all, delete-orphan")

class Finding(Base):
    """Security findings from jobs"""
    __tablename__ = "findings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    
    # Finding details
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(Enum(Severity), default=Severity.INFO)
    
    # Classification
    finding_type = Column(String(100))
    cve_id = Column(String(50))
    cwe_id = Column(String(50))
    mitre_technique = Column(String(50))  # T1234
    
    # Evidence
    target = Column(String(500))
    evidence = Column(Text)
    proof_of_concept = Column(Text)
    screenshots = Column(JSONB, default=[])
    
    # Remediation
    remediation = Column(Text)
    references = Column(JSONB, default=[])
    
    # Status
    is_false_positive = Column(Boolean, default=False)
    verified = Column(Boolean, default=False)
    
    # Metadata
    raw_output = Column(Text)
    tool_used = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    job = relationship("Job", back_populates="findings")

class RiskScore(Base):
    """Risk scores for jobs"""
    __tablename__ = "risk_scores"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False, unique=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    
    # Risk scores
    overall_score = Column(Integer, nullable=False)  # 0-100
    attack_surface_score = Column(Integer, nullable=False)
    exploitability_score = Column(Integer, nullable=False)
    impact_score = Column(Integer, nullable=False)
    
    # Risk level
    risk_level = Column(String(20), nullable=False)  # critical, high, medium, low
    
    # Severity breakdown
    severity_breakdown = Column(JSONB, default={})
    
    # Metadata
    total_findings = Column(Integer, default=0)
    calculated_at = Column(DateTime, default=datetime.utcnow)
    
    # Recommendations
    recommendations = Column(JSONB, default=[])

# =============================================================================
# POLICY MANAGEMENT
# =============================================================================

class Policy(Base):
    """Security policies for job execution"""
    __tablename__ = "policies"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Tool restrictions
    allowed_tools = Column(JSONB, default=[])
    blocked_tools = Column(JSONB, default=[])
    
    # Intensity limits
    max_intensity = Column(String(20), default="medium")
    
    # Rate limits
    max_requests_per_minute = Column(Integer, default=100)
    max_concurrent_scans = Column(Integer, default=5)
    
    # Time restrictions
    allowed_hours = Column(JSONB)  # {"start": "09:00", "end": "17:00", "timezone": "UTC"}
    allowed_days = Column(JSONB, default=["mon", "tue", "wed", "thu", "fri"])
    
    # Notifications
    notify_on_critical = Column(Boolean, default=True)
    notify_on_completion = Column(Boolean, default=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="policies")

# =============================================================================
# AUDIT LOGGING
# =============================================================================

class AuditLog(Base):
    """Full audit trail of all actions"""
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"))
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    
    # Action details
    action = Column(String(100), nullable=False)  # job.create, scope.approve, etc.
    resource_type = Column(String(50))
    resource_id = Column(UUID(as_uuid=True))
    
    # Request details
    request_id = Column(String(100))
    ip_address = Column(String(50))
    user_agent = Column(String(500))
    
    # Changes
    changes = Column(JSONB)  # {field: {old: x, new: y}}
    
    # Outcome
    success = Column(Boolean, default=True)
    error_message = Column(Text)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)

# =============================================================================
# SCHEDULED JOBS (Continuous Scanning)
# =============================================================================

class ScheduledJob(Base):
    """Scheduled jobs for continuous scanning"""
    __tablename__ = "scheduled_jobs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    
    # Schedule configuration
    name = Column(String(255), nullable=False)
    description = Column(Text)
    schedule = Column(String(100), nullable=False)  # Cron expression: "0 2 * * *"
    timezone = Column(String(50), default="UTC")
    
    # Job template (what to run)
    job_template = Column(JSONB, nullable=False)  # Contains: scope_id, phase, targets, intensity, etc.
    
    # Status
    is_active = Column(Boolean, default=True)
    is_paused = Column(Boolean, default=False)
    
    # Execution tracking
    last_run = Column(DateTime)
    next_run = Column(DateTime)
    total_runs = Column(Integer, default=0)
    successful_runs = Column(Integer, default=0)
    failed_runs = Column(Integer, default=0)
    
    # Error handling
    max_retries = Column(Integer, default=3)
    retry_delay_seconds = Column(Integer, default=300)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    tenant = relationship("Tenant")

# =============================================================================
# WORKSPACES (Team Collaboration)
# =============================================================================

class Workspace(Base):
    """Shared workspace for team collaboration"""
    __tablename__ = "workspaces"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    
    # Workspace details
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Settings
    is_default = Column(Boolean, default=False)
    settings = Column(JSONB, default={})
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    tenant = relationship("Tenant")
    members = relationship("WorkspaceMember", back_populates="workspace", cascade="all, delete-orphan")

class WorkspaceMember(Base):
    """Workspace membership with roles"""
    __tablename__ = "workspace_members"
    
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), primary_key=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    
    # Role: admin, member, viewer
    role = Column(String(50), default="member")
    
    # Permissions
    can_create_jobs = Column(Boolean, default=True)
    can_edit_findings = Column(Boolean, default=True)
    can_delete = Column(Boolean, default=False)
    
    # Metadata
    joined_at = Column(DateTime, default=datetime.utcnow)
    invited_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    
    # Relationships
    workspace = relationship("Workspace", back_populates="members")

class FindingComment(Base):
    """Comments on findings for collaboration"""
    __tablename__ = "finding_comments"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"))
    
    # Comment content
    comment = Column(Text, nullable=False)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    edited = Column(Boolean, default=False)

class ActivityLog(Base):
    """Activity feed for workspace collaboration"""
    __tablename__ = "activity_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    
    # Activity details
    activity_type = Column(String(100), nullable=False)  # job.created, finding.commented, etc.
    resource_type = Column(String(50))  # job, finding, scope, etc.
    resource_id = Column(UUID(as_uuid=True))
    
    # Activity description
    title = Column(String(500))
    description = Column(Text)
    activity_metadata = Column(JSONB, default={})
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)

class CommandLog(Base):
    """Log of all commands executed"""
    __tablename__ = "command_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    
    # Command details
    command = Column(Text, nullable=False)
    tool = Column(String(100))
    target = Column(String(500))
    
    # Policy
    policy_decision = Column(String(50))  # allowed, blocked, modified
    policy_reason = Column(Text)
    
    # Execution
    exit_code = Column(Integer)
    stdout = Column(Text)
    stderr = Column(Text)
    duration_ms = Column(Integer)
    
    # Metadata
    executed_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    job = relationship("Job", back_populates="commands")

class LLMLog(Base):
    """Log of all LLM interactions"""
    __tablename__ = "llm_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    
    # Model details
    model = Column(String(100), nullable=False)
    provider = Column(String(50))
    
    # Token usage
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    total_tokens = Column(Integer, default=0)
    
    # Cost
    cost_usd = Column(Integer, default=0)  # Stored as micro-dollars
    
    # Messages (encrypted in production)
    messages = Column(JSONB)
    response = Column(Text)
    
    # Performance
    latency_ms = Column(Integer)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
