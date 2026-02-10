# Advanced Techniques

## Ticket Operations
- Use `asktgs` to request service tickets for specific SPNs and keep requests narrowly scoped.
- Use `tgssub` to substitute the service name on an existing TGS only when the service boundary is explicitly approved.

## Operational Safety
- Prefer targeted SPNs or users rather than bulk roasting.
- Record the exact command and target principal for each ticket operation.

## Evidence
- Store ticket artifacts and command output for each action.
