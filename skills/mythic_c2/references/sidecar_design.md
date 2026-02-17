# Mythic C2 Sidecar Deployment Design

## Why Sidecar (Not Inside Kali Container)

Mythic is a complex multi-container orchestrator. It requires:
- **Docker-in-Docker** (it manages its own containers via docker-compose)
- **PostgreSQL** database (persistent state)
- **RabbitMQ** message broker (agent ↔ server communication)
- **Multiple ports** (7443 web UI, 5432 postgres, 5672 rabbitmq, dynamic agent ports)
- **Significant resources** (2+ CPU, 4GB+ RAM minimum)
- **Agent containers** that are dynamically started/stopped (Apollo, Poseidon, Medusa)

Embedding all of this inside the Kali executor container would:
1. **Bloat the Kali image** from ~2GB to 8-10GB+
2. **Require Docker-in-Docker** inside the Kali container (complex, security risk)
3. **Conflict with resource limits** on the executor container
4. **Break container isolation** between C2 infrastructure and pentesting tools
5. **Prevent Mythic reuse** across multiple concurrent jobs

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Docker Network                      │
│                 (tazosploit_c2)                       │
│                                                       │
│  ┌──────────────────┐    ┌─────────────────────────┐ │
│  │  Kali Executor   │    │   Mythic Sidecar        │ │
│  │                  │    │                          │ │
│  │  - Pentest tools │◄──►│  - mythic_server :7443  │ │
│  │  - Dynamic Agent │    │  - mythic_postgres      │ │
│  │  - mythic_c2.py  │    │  - mythic_rabbitmq      │ │
│  │  - Python mythic │    │  - mythic_react          │ │
│  │    PyPi package  │    │  - mythic_nginx          │ │
│  │                  │    │  - Agent containers      │ │
│  │  Env:            │    │    (Apollo, Poseidon,    │ │
│  │  MYTHIC_URL=     │    │     Medusa)              │ │
│  │  https://mythic: │    │  - C2 Profile containers │ │
│  │  7443            │    │    (HTTP, SMB, TCP)      │ │
│  │  MYTHIC_API_KEY= │    │                          │ │
│  │  <from .env>     │    │  Ports:                  │ │
│  └──────────────────┘    │  7443 — Web UI + API     │ │
│                          │  7000-7010 — Dynamic     │ │
│                          │  (agent listeners)        │ │
│                          └─────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

## Docker Compose Fragment (Sidecar Service)

```yaml
# docker-compose.mythic-sidecar.yml
# Launched by the TazoSploit orchestrator when C2_FRAMEWORK=mythic

version: '3.8'

services:
  mythic:
    image: itsafeaturemythic/mythic_go_server:latest
    container_name: mythic_server
    restart: unless-stopped
    networks:
      - tazosploit_c2
    volumes:
      - mythic_data:/opt/mythic
      - /var/run/docker.sock:/var/run/docker.sock  # DinD for agent containers
    environment:
      - MYTHIC_ADMIN_USER=${MYTHIC_ADMIN_USER:-mythic_admin}
      - MYTHIC_ADMIN_PASSWORD=${MYTHIC_ADMIN_PASSWORD}
      - MYTHIC_API_KEY=${MYTHIC_API_KEY}
      - NGINX_PORT=7443
      - NGINX_USE_SSL=true
      - MYTHIC_SERVER_DYNAMIC_PORTS=7000-7010,1080
      - MYTHIC_SERVER_DYNAMIC_PORTS_BIND_LOCALHOST_ONLY=false
      - RABBITMQ_BIND_LOCALHOST_ONLY=false
      - MYTHIC_SERVER_BIND_LOCALHOST_ONLY=false
    ports:
      - "7443:7443"
      - "7000-7010:7000-7010"
    healthcheck:
      test: ["CMD", "curl", "-fsSk", "https://localhost:7443/health"]
      interval: 30s
      timeout: 10s
      retries: 5
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G

volumes:
  mythic_data:

networks:
  tazosploit_c2:
    driver: bridge
```

## Kali Container Additions (Dockerfile Fragment)

The Kali executor only needs the Mythic Python scripting library and the
automation script. No Mythic server components.

```dockerfile
# ── Mythic C2 client dependencies ──────────────────────────────────────
# Install the Mythic scripting PyPi package for API automation
RUN pip install --no-cache-dir mythic aiohttp gql[aiohttp]

# Copy TazoSploit Mythic automation script
COPY scripts/mythic_c2.py /opt/tazosploit/scripts/mythic_c2.py
RUN chmod +x /opt/tazosploit/scripts/mythic_c2.py

# Default environment (overridden at runtime by orchestrator)
ENV MYTHIC_URL="https://mythic:7443" \
    MYTHIC_SSL_VERIFY="false" \
    MYTHIC_DEFAULT_AGENT="apollo"
# MYTHIC_API_KEY is injected at runtime by the orchestrator
```

## Orchestrator Integration Points

### Job Startup (when C2_FRAMEWORK=mythic)
1. Orchestrator checks if Mythic sidecar is running (`docker inspect mythic_server`)
2. If not running, start via `docker-compose -f docker-compose.mythic-sidecar.yml up -d`
3. Wait for healthcheck to pass (max 120s)
4. Read `MYTHIC_API_KEY` from Mythic `.env` file
5. Inject `MYTHIC_URL` and `MYTHIC_API_KEY` into Kali executor environment
6. Install required agents: `mythic-cli install github https://github.com/MythicAgents/Apollo.git`

### During Job
- Kali executor communicates with Mythic via HTTPS GraphQL API only
- No direct Docker access needed from Kali container
- `mythic_c2.py` handles all API interactions

### Job Cleanup
1. Kill all active callbacks created during the job
2. Remove generated payloads
3. Optionally stop Mythic sidecar (if `C2_CLEANUP_SIDECAR=true`)
4. Persist Mythic database for forensic review

## Feature Flag Integration

```python
# In c2_phase_gate.py, extend the existing C2 framework selection:
C2_FRAMEWORK = os.getenv("C2_FRAMEWORK", "sliver").lower()  # sliver | mythic | empire

# The phase gate already supports C2_DEPLOY phase.
# For Mythic, the same flow applies:
#   EXPLOITATION → C2_DEPLOY (generate Mythic payload, deliver, verify callback) → POST_EXPLOIT
```

## Security Considerations

1. **API Key Rotation**: Generate unique API key per job, revoke after completion
2. **Network Isolation**: Mythic sidecar on dedicated Docker network, not exposed to internet
3. **Credential Storage**: All credentials harvested via Mythic are encrypted at rest
4. **Audit Trail**: Mythic's built-in operation tracking provides complete audit log
5. **Docker Socket**: Mythic needs Docker socket access — restrict via AppArmor/seccomp
6. **TLS**: Always use HTTPS between Kali executor and Mythic (self-signed OK for internal)
