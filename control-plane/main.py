"""
NeuroSploit SaaS v2 - Control Plane API
Handles tenant management, authorization, job orchestration, and audit logging
"""

import os
import uuid
import logging
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog
import redis.asyncio as redis

from api.database import engine, get_db
from api.models import Base
from api.routers import tenants, scopes, jobs, policies, audit
from api.auth import get_current_user
from services.transaction_logger import TransactionLogger

# =============================================================================
# STRUCTURED LOGGING CONFIGURATION
# =============================================================================

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# =============================================================================
# APPLICATION LIFECYCLE
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown"""
    
    # Startup
    logger.info("control_plane_starting", version="2.0.0")
    
    # Initialize database
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("database_initialized")
    
    # Initialize Redis connection
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    app.state.redis = redis.from_url(redis_url, decode_responses=True)
    await app.state.redis.ping()
    logger.info("redis_connected", url=redis_url)
    
    # Initialize transaction logger
    app.state.transaction_logger = TransactionLogger(
        log_dir=os.getenv("LOG_DIR", "/app/logs")
    )
    logger.info("transaction_logger_initialized")
    
    yield
    
    # Shutdown
    logger.info("control_plane_shutting_down")
    await app.state.redis.close()

# =============================================================================
# FASTAPI APPLICATION
# =============================================================================

app = FastAPI(
    title="NeuroSploit SaaS v2 - Control Plane",
    description="Multi-tenant AI-powered penetration testing platform",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# =============================================================================
# MIDDLEWARE
# =============================================================================

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all API requests with full details"""
    
    request_id = str(uuid.uuid4())
    start_time = datetime.utcnow()
    
    # Add request ID to context
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(request_id=request_id)
    
    # Log request
    logger.info(
        "api_request_started",
        method=request.method,
        path=request.url.path,
        client_ip=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", "unknown")
    )
    
    # Process request
    response = await call_next(request)
    
    # Calculate duration
    duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
    
    # Log response
    logger.info(
        "api_request_completed",
        status_code=response.status_code,
        duration_ms=round(duration_ms, 2)
    )
    
    # Add request ID to response headers
    response.headers["X-Request-ID"] = request_id
    
    return response

# =============================================================================
# EXCEPTION HANDLERS
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.warning(
        "http_exception",
        status_code=exc.status_code,
        detail=exc.detail,
        path=request.url.path
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "request_id": request.headers.get("X-Request-ID", "unknown")
        }
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(
        "unhandled_exception",
        error=str(exc),
        path=request.url.path,
        exc_info=True
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "request_id": request.headers.get("X-Request-ID", "unknown")
        }
    )

# =============================================================================
# HEALTH ENDPOINTS
# =============================================================================

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "control-plane",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health/detailed")
async def detailed_health():
    """Detailed health check with dependency status"""
    
    # Check Redis
    try:
        await app.state.redis.ping()
        redis_status = "healthy"
    except Exception as e:
        redis_status = f"unhealthy: {str(e)}"
    
    # Check Database
    try:
        async with engine.connect() as conn:
            await conn.execute("SELECT 1")
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
    
    return {
        "status": "healthy" if all([
            redis_status == "healthy",
            db_status == "healthy"
        ]) else "degraded",
        "service": "control-plane",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "dependencies": {
            "redis": redis_status,
            "database": db_status
        }
    }

# =============================================================================
# METRICS ENDPOINT
# =============================================================================

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    # TODO: Implement proper Prometheus metrics
    return {
        "api_requests_total": 0,
        "active_jobs": 0,
        "tenants_total": 0
    }

# =============================================================================
# ROUTERS
# =============================================================================

# Include API routers
app.include_router(tenants.router, prefix="/api/v1/tenants", tags=["Tenants"])
app.include_router(scopes.router, prefix="/api/v1/scopes", tags=["Scopes"])
app.include_router(jobs.router, prefix="/api/v1/jobs", tags=["Jobs"])
app.include_router(policies.router, prefix="/api/v1/policies", tags=["Policies"])
app.include_router(audit.router, prefix="/api/v1/audit", tags=["Audit"])

# Import and include additional routers
from api.routers import mitre, scheduled_jobs, workspaces, reports, attack_graphs
app.include_router(mitre.router, prefix="/api/v1/mitre", tags=["MITRE ATT&CK"])
app.include_router(scheduled_jobs.router, prefix="/api/v1/scheduled-jobs", tags=["Scheduled Jobs"])
app.include_router(workspaces.router, prefix="/api/v1/workspaces", tags=["Workspaces"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(attack_graphs.router, prefix="/api/v1/attack-graphs", tags=["Attack Graphs"])

# =============================================================================
# ROOT ENDPOINT
# =============================================================================

@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "service": "NeuroSploit SaaS v2 - Control Plane",
        "version": "2.0.0",
        "docs": "/api/docs",
        "health": "/health"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=os.getenv("ENVIRONMENT") == "development"
    )
