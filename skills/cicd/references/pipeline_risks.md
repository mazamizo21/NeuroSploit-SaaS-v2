# Pipeline Risk Patterns

## Goals
1. Identify risky pipeline configurations in read-only mode.
2. Flag insecure artifact or build settings.
3. Record evidence tied to specific pipeline files.

## Safe Checks
1. Review pipeline definitions for unsigned artifacts.
2. Review pipeline definitions for secrets in logs or environment.
3. Review pipeline definitions for unpinned build images.
4. Review pipeline definitions for over-privileged runners.
5. Review pipeline definitions for disabled approvals or protections.

## Evidence Checklist
1. Pipeline file paths and relevant snippets (redacted).
2. Risk classification and impact notes.
3. References to job names and stages.
