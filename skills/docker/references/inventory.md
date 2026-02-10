# Docker Inventory

## Goals
1. Capture containers, images, networks, and volumes.
2. Record host OS and daemon configuration summaries.
3. Note privileged or host-mounted containers.

## Safe Checks
1. `docker info`
2. `docker ps -a`
3. `docker images`
4. `docker volume ls` and `docker network ls` (read-only)

## Indicators to Record
1. Privileged containers.
2. Containers running as root.
3. Sensitive mounts.
4. Host network mode usage.

## Evidence Checklist
1. Container count and sample names.
2. Image list summary.
3. Network and volume counts.
4. Privileged container list evidence.
