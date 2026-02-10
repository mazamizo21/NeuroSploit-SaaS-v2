# Authentication Endpoints

## Goals
1. Identify Drupal login endpoints safely.
2. Record authentication surface and status behavior.

## Safe Checks
1. Check `/user/login` and `/user/password`.
2. Avoid brute force unless explicitly authorized.
3. Record response codes and redirects.

## Evidence Checklist
1. Endpoint availability and status codes.
2. Notes on exposed admin pages.
3. Redirect chains and auth policy hints.
