# Loot Vault (Per-Job Scope)

## Overview
Loot Vault is now scoped **per job** and no longer exists as a standalone tab. Loot appears only inside each pentest job detail view, preventing cross-job mixing of credentials, tokens, or evidence.

## UX Changes
- Loot Vault is embedded in each **Pentest Job** detail page.
- The global **Loot Vault** sidebar entry is removed.
- Loot stats and items are filtered to the active job only.

## API Behavior
The existing endpoints now support a `job_id` filter:
- `GET /api/v1/loot?job_id=<job_id>&loot_type=<type>`
- `GET /api/v1/loot/stats?job_id=<job_id>`

`job_id` is now **required**, so tenant-wide aggregation is not possible.

## Where To Find Loot
Open a specific pentest job and scroll to **Loot Vault (Job Only)**.
You can jump directly via:
```
/pentests/<job_id>#loot-vault
```

## Files Updated
- `frontend/src/app/pentests/[id]/page.tsx`
- `frontend/src/components/Sidebar.tsx`
- `control-plane/api/routers/loot.py`
Removed: `frontend/src/app/loot/page.tsx`, `frontend/src/app/loot/LootPageClient.tsx`
