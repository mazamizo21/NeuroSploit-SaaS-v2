#!/usr/bin/env bash
# tools-update.sh — Refresh/update all Sliver C2 + evasion tools inside the Kali container.
# Run this inside the container to pull latest versions without rebuilding the image.
# Usage: /opt/tazosploit/scripts/tools-update.sh

set -euo pipefail

LOGFILE="/pentest/logs/tools-update-$(date -u '+%Y%m%d-%H%M%S').log"
mkdir -p "$(dirname "$LOGFILE")"

log() {
    local msg="[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $1"
    echo "$msg" | tee -a "$LOGFILE"
}

log "============================================="
log "  TazoSploit Tools Update"
log "============================================="

UPDATED=0
FAILED=0
SKIPPED=0

# --- 1. Sliver Client (download latest arm64 binary) ---
log ""
log "[1/5] Updating sliver-client..."
OLD_VERSION=$(sliver-client version 2>/dev/null | head -1 || echo "unknown")
if curl -sSL -o /tmp/sliver-client-new \
    "https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux-arm64" 2>>"$LOGFILE"; then
    chmod +x /tmp/sliver-client-new
    # Sanity check: new binary should be > 10MB
    SIZE=$(stat -c%s /tmp/sliver-client-new 2>/dev/null || stat -f%z /tmp/sliver-client-new 2>/dev/null || echo "0")
    if [ "$SIZE" -gt 10000000 ]; then
        mv /tmp/sliver-client-new /usr/local/bin/sliver-client
        NEW_VERSION=$(sliver-client version 2>/dev/null | head -1 || echo "unknown")
        log "  Updated: $OLD_VERSION -> $NEW_VERSION"
        UPDATED=$((UPDATED + 1))
    else
        log "  FAILED: Downloaded binary too small (${SIZE} bytes), keeping old version"
        rm -f /tmp/sliver-client-new
        FAILED=$((FAILED + 1))
    fi
else
    log "  FAILED: Download failed, keeping old version"
    FAILED=$((FAILED + 1))
fi

# --- 2. ScareCrow (git pull + rebuild) ---
log ""
log "[2/5] Updating ScareCrow..."
if [ -d /opt/ScareCrow ]; then
    cd /opt/ScareCrow
    OLD_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    if git pull --ff-only 2>>"$LOGFILE"; then
        NEW_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
        if [ "$OLD_COMMIT" != "$NEW_COMMIT" ]; then
            log "  Source updated: $OLD_COMMIT -> $NEW_COMMIT"
            if go build -o /usr/local/bin/ScareCrow . 2>>"$LOGFILE"; then
                log "  Rebuilt successfully"
                UPDATED=$((UPDATED + 1))
            else
                log "  FAILED: Build failed after update"
                FAILED=$((FAILED + 1))
            fi
        else
            log "  Already up to date ($OLD_COMMIT)"
            SKIPPED=$((SKIPPED + 1))
        fi
    else
        log "  FAILED: git pull failed"
        FAILED=$((FAILED + 1))
    fi
else
    log "  SKIPPED: /opt/ScareCrow not found"
    SKIPPED=$((SKIPPED + 1))
fi

# --- 3. Donut (git pull + rebuild) ---
log ""
log "[3/5] Updating Donut..."
if [ -d /opt/donut ]; then
    cd /opt/donut
    OLD_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    if git pull --ff-only 2>>"$LOGFILE"; then
        NEW_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
        if [ "$OLD_COMMIT" != "$NEW_COMMIT" ]; then
            log "  Source updated: $OLD_COMMIT -> $NEW_COMMIT"
            make clean 2>>"$LOGFILE" || true
            if make 2>>"$LOGFILE"; then
                cp /opt/donut/donut /usr/local/bin/donut
                chmod +x /usr/local/bin/donut
                log "  Rebuilt successfully"
                UPDATED=$((UPDATED + 1))
            else
                log "  FAILED: Build failed after update"
                FAILED=$((FAILED + 1))
            fi
        else
            log "  Already up to date ($OLD_COMMIT)"
            SKIPPED=$((SKIPPED + 1))
        fi
    else
        log "  FAILED: git pull failed"
        FAILED=$((FAILED + 1))
    fi
else
    log "  SKIPPED: /opt/donut not found"
    SKIPPED=$((SKIPPED + 1))
fi

# --- 4. SharpCollection (git pull) ---
log ""
log "[4/5] Updating SharpCollection..."
if [ -d /opt/sharp-collection ]; then
    cd /opt/sharp-collection
    OLD_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    if git pull --ff-only 2>>"$LOGFILE"; then
        NEW_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
        if [ "$OLD_COMMIT" != "$NEW_COMMIT" ]; then
            log "  Updated: $OLD_COMMIT -> $NEW_COMMIT"
            UPDATED=$((UPDATED + 1))
        else
            log "  Already up to date ($OLD_COMMIT)"
            SKIPPED=$((SKIPPED + 1))
        fi
    else
        log "  FAILED: git pull failed"
        FAILED=$((FAILED + 1))
    fi
else
    log "  SKIPPED: /opt/sharp-collection not found"
    SKIPPED=$((SKIPPED + 1))
fi

# --- 5. sliver-py (pip upgrade) ---
log ""
log "[5/5] Updating sliver-py + donut-shellcode..."
OLD_SLIVER_PY=$(pip3 show sliver-py 2>/dev/null | grep Version | awk '{print $2}' || echo "unknown")
if pip3 install --break-system-packages --no-cache-dir --upgrade sliver-py grpcio protobuf donut-shellcode 2>>"$LOGFILE"; then
    NEW_SLIVER_PY=$(pip3 show sliver-py 2>/dev/null | grep Version | awk '{print $2}' || echo "unknown")
    if [ "$OLD_SLIVER_PY" != "$NEW_SLIVER_PY" ]; then
        log "  sliver-py updated: $OLD_SLIVER_PY -> $NEW_SLIVER_PY"
        UPDATED=$((UPDATED + 1))
    else
        log "  Python packages already up to date"
        SKIPPED=$((SKIPPED + 1))
    fi
else
    log "  FAILED: pip upgrade failed"
    FAILED=$((FAILED + 1))
fi

# --- Summary ---
log ""
log "============================================="
log "  Update Complete"
log "  Updated: $UPDATED  Skipped: $SKIPPED  Failed: $FAILED"
log "  Log: $LOGFILE"
log "============================================="

# Run verification after update
log ""
log "Running tool verification..."
if /opt/tazosploit/scripts/verify-tools.sh 2>&1 | tee -a "$LOGFILE"; then
    log "All tools verified after update."
else
    log "WARNING: Some tools failed verification after update."
fi

exit $FAILED
