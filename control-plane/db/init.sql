-- TazoSploit SaaS v2 - Database Initialization
-- Creates tables, indexes, and seed data for development

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenant tiers enum
CREATE TYPE tenant_tier AS ENUM ('free', 'pro', 'enterprise');

-- Job status enum
CREATE TYPE job_status AS ENUM ('pending', 'queued', 'running', 'completed', 'failed', 'cancelled', 'timeout');

-- Severity enum
CREATE TYPE severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');

-- =============================================================================
-- TENANTS
-- =============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    tier tenant_tier DEFAULT 'free',
    max_concurrent_jobs INTEGER DEFAULT 1,
    max_scopes INTEGER DEFAULT 5,
    max_monthly_jobs INTEGER DEFAULT 10,
    api_key_hash VARCHAR(255),
    encryption_key_id VARCHAR(255),
    api_key_encrypted TEXT,
    subscription_token_encrypted TEXT,
    domain_verified BOOLEAN DEFAULT FALSE,
    payment_verified BOOLEAN DEFAULT FALSE,
    kyc_verified BOOLEAN DEFAULT FALSE,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_tenants_slug ON tenants(slug);

-- =============================================================================
-- USERS
-- =============================================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    full_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'operator',
    is_active BOOLEAN DEFAULT TRUE,
    email_verified BOOLEAN DEFAULT FALSE,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);

-- =============================================================================
-- SCOPES (Target Authorization)
-- =============================================================================

CREATE TABLE IF NOT EXISTS scopes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    targets JSONB NOT NULL,
    excluded_targets JSONB DEFAULT '[]',
    authorization_type VARCHAR(50),
    authorization_proof TEXT,
    authorization_expires TIMESTAMP,
    allowed_phases JSONB DEFAULT '["RECON", "VULN_SCAN"]',
    max_intensity VARCHAR(20) DEFAULT 'medium',
    allowed_hours JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    approved_at TIMESTAMP,
    approved_by UUID,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_scopes_tenant ON scopes(tenant_id);

-- =============================================================================
-- JOBS
-- =============================================================================

CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scope_id UUID REFERENCES scopes(id) ON DELETE SET NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    phase VARCHAR(50) NOT NULL,
    targets JSONB NOT NULL,
    target_type VARCHAR(20) DEFAULT 'lab',
    intensity VARCHAR(20) DEFAULT 'medium',
    timeout_seconds INTEGER DEFAULT 3600,
    auto_run BOOLEAN DEFAULT FALSE,
    max_iterations INTEGER DEFAULT 30,
    authorization_confirmed BOOLEAN DEFAULT FALSE,
    exploit_mode VARCHAR(20) DEFAULT 'explicit_only',
    llm_provider VARCHAR(100),
    allow_persistence BOOLEAN DEFAULT FALSE,
    allow_defense_evasion BOOLEAN DEFAULT FALSE,
    allow_scope_expansion BOOLEAN DEFAULT FALSE,
    enable_session_handoff BOOLEAN DEFAULT FALSE,
    enable_target_rotation BOOLEAN DEFAULT TRUE,
    target_focus_window INTEGER DEFAULT 6,
    target_focus_limit INTEGER DEFAULT 30,
    target_min_commands INTEGER DEFAULT 8,
    status job_status DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    worker_id VARCHAR(100),
    container_id VARCHAR(100),
    findings_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    tokens_used INTEGER DEFAULT 0,
    cost_usd INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0
);

CREATE INDEX idx_jobs_tenant ON jobs(tenant_id);
CREATE INDEX idx_jobs_status ON jobs(status);
CREATE INDEX idx_jobs_created ON jobs(created_at DESC);

-- =============================================================================
-- FINDINGS
-- =============================================================================

CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity severity DEFAULT 'info',
    finding_type VARCHAR(100),
    cve_id VARCHAR(50),
    cwe_id VARCHAR(50),
    mitre_technique VARCHAR(50),
    target VARCHAR(500),
    evidence TEXT,
    proof_of_concept TEXT,
    screenshots JSONB DEFAULT '[]',
    remediation TEXT,
    "references" JSONB DEFAULT '[]',
    is_false_positive BOOLEAN DEFAULT FALSE,
    verified BOOLEAN DEFAULT FALSE,
    raw_output TEXT,
    tool_used VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_findings_job ON findings(job_id);
CREATE INDEX idx_findings_severity ON findings(severity);

-- =============================================================================
-- POLICIES
-- =============================================================================

CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    allowed_tools JSONB DEFAULT '[]',
    blocked_tools JSONB DEFAULT '[]',
    max_intensity VARCHAR(20) DEFAULT 'medium',
    max_requests_per_minute INTEGER DEFAULT 100,
    max_concurrent_scans INTEGER DEFAULT 5,
    allowed_hours JSONB,
    allowed_days JSONB DEFAULT '["mon", "tue", "wed", "thu", "fri"]',
    notify_on_critical BOOLEAN DEFAULT TRUE,
    notify_on_completion BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_policies_tenant ON policies(tenant_id);

-- =============================================================================
-- AUDIT LOGS
-- =============================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    request_id VARCHAR(100),
    ip_address VARCHAR(50),
    user_agent VARCHAR(500),
    changes JSONB,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_tenant ON audit_logs(tenant_id);
CREATE INDEX idx_audit_created ON audit_logs(created_at DESC);

-- =============================================================================
-- COMMAND LOGS
-- =============================================================================

CREATE TABLE IF NOT EXISTS command_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    command TEXT NOT NULL,
    tool VARCHAR(100),
    target VARCHAR(500),
    policy_decision VARCHAR(50),
    policy_reason TEXT,
    exit_code INTEGER,
    stdout TEXT,
    stderr TEXT,
    duration_ms INTEGER,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_command_logs_job ON command_logs(job_id);

-- =============================================================================
-- LLM LOGS
-- =============================================================================

CREATE TABLE IF NOT EXISTS llm_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    model VARCHAR(100) NOT NULL,
    provider VARCHAR(50),
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,
    cost_usd INTEGER DEFAULT 0,
    messages JSONB,
    response TEXT,
    latency_ms INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_llm_logs_job ON llm_logs(job_id);

-- =============================================================================
-- SEED DATA FOR DEVELOPMENT
-- =============================================================================

-- Default tenant
INSERT INTO tenants (id, name, slug, tier, max_concurrent_jobs, max_scopes, max_monthly_jobs)
VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'Development Tenant',
    'dev',
    'enterprise',
    10,
    100,
    1000
) ON CONFLICT (slug) DO NOTHING;

-- Default admin user (password: admin123)
INSERT INTO users (id, tenant_id, email, password_hash, full_name, role, is_active, email_verified)
VALUES (
    'b0000000-0000-0000-0000-000000000001',
    'a0000000-0000-0000-0000-000000000001',
    'admin@tazosploit.local',
    '$2b$12$JgWFLH2n6UM3hLxbqJw5C.cXbYnpEkRJ1CYyP4rKtGFGDFGpLkzBS',
    'Admin User',
    'admin',
    TRUE,
    TRUE
) ON CONFLICT (email) DO NOTHING;

-- Default scope (DVWA for testing)
INSERT INTO scopes (id, tenant_id, name, description, targets, allowed_phases, max_intensity)
VALUES (
    'c0000000-0000-0000-0000-000000000001',
    'a0000000-0000-0000-0000-000000000001',
    'DVWA Test Target',
    'Damn Vulnerable Web Application for testing',
    '["dvwa", "172.17.0.0/16", "localhost"]',
    '["RECON", "VULN_SCAN", "EXPLOIT", "POST_EXPLOIT", "LATERAL", "FULL", "REPORT"]',
    'high'
) ON CONFLICT DO NOTHING;

-- Default policy
INSERT INTO policies (id, tenant_id, name, description, is_default, is_active)
VALUES (
    'd0000000-0000-0000-0000-000000000001',
    'a0000000-0000-0000-0000-000000000001',
    'Default Policy',
    'Default security policy for all jobs',
    TRUE,
    TRUE
) ON CONFLICT DO NOTHING;

-- =============================================================================
-- LOOT VAULT
-- =============================================================================

CREATE TABLE IF NOT EXISTS loot (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    loot_type VARCHAR(50) NOT NULL,  -- credential, hash, token, config, db_sample, session
    source VARCHAR(500) NOT NULL,
    value JSONB NOT NULL DEFAULT '{}',
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_loot_job ON loot(job_id);
CREATE INDEX idx_loot_tenant ON loot(tenant_id);
CREATE INDEX idx_loot_type ON loot(loot_type);

-- =============================================================================
-- ACTIVE TERMINAL SESSIONS
-- =============================================================================

CREATE TABLE IF NOT EXISTS active_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    job_id UUID REFERENCES jobs(id) ON DELETE SET NULL,
    container_name VARCHAR(255) NOT NULL,
    tmux_session VARCHAR(100) NOT NULL,
    label VARCHAR(255),
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sessions_tenant ON active_sessions(tenant_id);
CREATE INDEX idx_sessions_status ON active_sessions(status);

-- =============================================================================
-- EVIDENCE FILES (MinIO metadata)
-- =============================================================================

CREATE TABLE IF NOT EXISTS evidence_files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    bucket VARCHAR(100) NOT NULL DEFAULT 'evidence',
    object_key VARCHAR(500) NOT NULL,
    filename VARCHAR(255),
    content_type VARCHAR(100),
    size_bytes BIGINT DEFAULT 0,
    checksum VARCHAR(64),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_evidence_job ON evidence_files(job_id);

-- =============================================================================
-- TUNNEL AGENTS (WireGuard VPN)
-- =============================================================================

CREATE TABLE IF NOT EXISTS tunnel_agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255),
    token_hash VARCHAR(255),
    token_used BOOLEAN DEFAULT false,
    wg_public_key TEXT,
    wg_assigned_ip VARCHAR(45),
    status VARCHAR(20) DEFAULT 'pending',
    last_heartbeat TIMESTAMPTZ,
    client_info JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_tunnel_agents_tenant ON tunnel_agents(tenant_id);
CREATE INDEX idx_tunnel_agents_status ON tunnel_agents(status);
CREATE INDEX idx_tunnel_agents_token ON tunnel_agents(token_hash);

-- =============================================================================
-- MIGRATIONS (idempotent)
-- =============================================================================

-- Add exploit_mode column to jobs
DO $$ BEGIN
    ALTER TABLE jobs ADD COLUMN exploit_mode VARCHAR(20) DEFAULT 'explicit_only';
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

-- Add llm_provider column to jobs
DO $$ BEGIN
    ALTER TABLE jobs ADD COLUMN llm_provider VARCHAR(100);
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

-- Add max_iterations column to jobs
DO $$ BEGIN
    ALTER TABLE jobs ADD COLUMN max_iterations INTEGER DEFAULT 30;
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

-- Add target rotation controls to jobs
DO $$ BEGIN
    ALTER TABLE jobs ADD COLUMN enable_target_rotation BOOLEAN DEFAULT TRUE;
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE jobs ADD COLUMN target_focus_window INTEGER DEFAULT 6;
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE jobs ADD COLUMN target_focus_limit INTEGER DEFAULT 30;
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE jobs ADD COLUMN target_min_commands INTEGER DEFAULT 8;
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

-- Add result JSONB column to jobs
DO $$ BEGIN
    ALTER TABLE jobs ADD COLUMN result JSONB DEFAULT '{}';
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

-- =============================================================================
-- API KEY MANAGEMENT (Phase 4)
-- =============================================================================

DO $$ BEGIN
    ALTER TABLE tenants ADD COLUMN api_key_encrypted TEXT;
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

-- =============================================================================
-- MITRE TECHNIQUE TRACKING (Phase 4)
-- =============================================================================

CREATE TABLE IF NOT EXISTS mitre_technique_hits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    technique_id VARCHAR(20) NOT NULL,
    tool VARCHAR(100),
    count INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mitre_hits_tenant ON mitre_technique_hits(tenant_id);
CREATE INDEX IF NOT EXISTS idx_mitre_hits_technique ON mitre_technique_hits(technique_id);

-- Database initialized successfully
