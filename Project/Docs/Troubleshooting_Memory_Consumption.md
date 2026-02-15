# High Memory Usage Investigation Log

**Date:** 2026-02-14
**Issue:** User reported a node process consuming high memory ("what is this node consuming my memory").

## Investigation
- Ran `ps` and `top` commands to identify node processes.
- Found highly active node process:
    - **PID:** 44809
    - **Name:** LM Studio Internal Node Process (`llmworker.js`)
    - **Command:** `/Users/tazjack/.lmstudio/.internal/utils/node ... llmworker.js`
    - **Memory Usage:** ~22.6 GB (RSS)
    - **Status:** Running (likely holding an LLM in memory).

- Also noted secondary high-memory process:
    - **PID:** 4690
    - **Name:** Antigravity Language Server / Helper
    - **Memory Usage:** ~5.7 GB (RSS)

## Root Cause
- LM Studio is running in the background with a large model loaded, consuming ~23GB of system RAM.
- Antigravity (IDE) processes are also consuming significant memory (~6GB), likely due to large project indexing or language server cache.

## Resolution
- Validated that the process is legitimate software (LM Studio) and not malware.
- Advised user to stop the model in LM Studio or quit the application to free up memory.
