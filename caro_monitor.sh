#!/bin/bash
# CARO Batch Monitor
# Runs experiments sequentially on a single rootainer container.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MONITOR_LOG="$SCRIPT_DIR/monitor.log"
MAX_RETRIES=3
EMAIL_INTERVAL=1800   # 30 minutes

# ── IDs to run (updated by setup_experiment.py) ───────────────────────────────
ARVO_IDS=(
    42474837
)

TOTAL=${#ARVO_IDS[@]}

# ── State files ───────────────────────────────────────────────────────────────
COUNT_FILE="$SCRIPT_DIR/.completed_count"
FAILED_FILE="$SCRIPT_DIR/.failed_ids"
HALT_FILE="$SCRIPT_DIR/.halt"

# ── Helpers ───────────────────────────────────────────────────────────────────
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$MONITOR_LOG"
}

notify() {
    python3 "$SCRIPT_DIR/send_notification.py" "$1" "$2" 2>>"$MONITOR_LOG" && \
        log "  ntfy sent: $1" || log "  ntfy FAILED: $1"
}

ntfy_topic() {
    python3 -c "
import json
try:
    cfg=json.load(open('$SCRIPT_DIR/config/notify_config.json'))
    m=cfg.get('method','ntfy')
    if m=='ntfy': print('ntfy: ' + cfg['ntfy']['url'].rstrip('/') + '/' + cfg['ntfy']['topic'])
    else: print('smtp: ' + cfg['smtp'].get('recipient','?'))
except: print('(notify_config.json not found)')
"
}

inc_completed() {
    count=$(( $(cat "$COUNT_FILE" 2>/dev/null || echo 0) + 1 ))
    echo $count > "$COUNT_FILE"
    echo $count
}

get_completed() {
    cat "$COUNT_FILE" 2>/dev/null || echo 0
}

get_failed_count() {
    wc -l < "$FAILED_FILE" 2>/dev/null | tr -d ' ' || echo 0
}

check_quota_error() {
    local logfile=$1
    grep -qiE \
        "insufficient_quota|rate_limit_exceeded|billing|quota.*exceeded|exceeded.*quota|credit|payment|529|too many requests|authentication.*failed|invalid.*api.*key|hit.*the.*limit|you.*hit.*limit|usage.*limit|exceeded.*usage|usage.*exceeded|limit.*reached|you.*reached.*limit|claude.*limit|out of.*credit" \
        "$logfile" 2>/dev/null
}

print_failed_and_remaining() {
    local failed_ids remaining_ids
    failed_ids=$(cat "$FAILED_FILE" 2>/dev/null | tr '\n' ' ' | xargs)
    echo ""
    echo "  FAILED IDs (exhausted retries):"
    echo "  ${failed_ids:-none}"
    echo ""
}

set_arvo_id() {
    local arvo_id=$1
    local cfg_file=$2
    python3 -c "
import json
with open('$cfg_file') as f: c=json.load(f)
c['arvo_id']=$arvo_id
with open('$cfg_file','w') as f: json.dump(c,f,indent=4)
"
}

# ── Periodic updater ──────────────────────────────────────────────────────────
updater() {
    while true; do
        sleep $EMAIL_INTERVAL
        completed=$(get_completed)
        failed=$(get_failed_count)
        remaining=$(( TOTAL - completed - failed ))
        status="Progress: $completed done / $failed failed / $remaining remaining (of $TOTAL)\n\n"
        last=$(tail -2 "$SCRIPT_DIR/caro.log" 2>/dev/null | tr '\n' ' ')
        status+="Last: $last\n"
        notify "CARO Update: $completed/$TOTAL done" "$status"
    done
}

# ── Main ──────────────────────────────────────────────────────────────────────
CFG="$SCRIPT_DIR/config/experiment_setup.json"

log "=========================================="
log " CARO Batch Monitor"
log " Total IDs : $TOTAL"
log " Channel   : $(ntfy_topic)"
log "=========================================="

# Print channel to screen
echo ""
echo "  Notifications → $(ntfy_topic)"
echo ""

# Init state — ensure clean slate
rm -f "$HALT_FILE"
echo 0 > "$COUNT_FILE"
> "$FAILED_FILE"

notify "CARO Batch Started (0/$TOTAL)" \
    "Starting $TOTAL experiments.\n\nIDs: ${ARVO_IDS[*]}\nChannel: $(ntfy_topic)"

# Start periodic updater in background
updater &
UPDATER_PID=$!

# ── Run experiments sequentially ─────────────────────────────────────────────
for arvo_id in "${ARVO_IDS[@]}"; do
    # Check halt flag before picking next ID
    if [ -f "$HALT_FILE" ]; then
        log "Halt signal detected — stopping"
        break
    fi

    log "── ARVO $arvo_id ──"
    set_arvo_id "$arvo_id" "$CFG"

    success=false
    for attempt in $(seq 1 $MAX_RETRIES); do
        [ -f "$HALT_FILE" ] && break

        log "Attempt $attempt/$MAX_RETRIES for $arvo_id"

        cd "$SCRIPT_DIR"
        python3 caro.py --config "$CFG" >> "$SCRIPT_DIR/caro.log" 2>&1
        EXIT_CODE=$?

        if [ $EXIT_CODE -eq 0 ]; then
            success=true
            log "SUCCESS: $arvo_id"
            break
        fi

        if check_quota_error "$SCRIPT_DIR/caro.log"; then
            log "USAGE LIMIT detected on $arvo_id — halting"
            echo "$arvo_id" >> "$FAILED_FILE"
            echo "$arvo_id" > "$HALT_FILE"

            echo ""
            echo "══════════════════════════════════════════════════════"
            echo "  USAGE LIMIT HIT — stopping"
            echo "  Triggered by ARVO $arvo_id"
            echo "══════════════════════════════════════════════════════"
            print_failed_and_remaining

            failed_ids=$(cat "$FAILED_FILE" 2>/dev/null | tr '\n' ' ' | xargs)
            notify "CARO HALTED — Usage Limit Hit" \
                "Hit the usage limit on ARVO $arvo_id.\n\nFailed IDs: ${failed_ids:-none}\n\nRestart after limit resets."
            break 2
        fi

        log "FAILED (exit $EXIT_CODE) attempt $attempt for $arvo_id"
        [ $attempt -lt $MAX_RETRIES ] && sleep 30
    done

    if $success; then
        completed=$(inc_completed)
        notify "CARO Done: $arvo_id ($completed/$TOTAL)" \
            "Completed ARVO $arvo_id.\nProgress: $completed/$TOTAL\n\nLog tail:\n$(tail -20 "$SCRIPT_DIR/caro.log")"
    elif [ ! -f "$HALT_FILE" ]; then
        echo "$arvo_id" >> "$FAILED_FILE"
        log "GAVE UP on $arvo_id after $MAX_RETRIES attempts"
        notify "CARO FAILED: $arvo_id" \
            "Failed ARVO $arvo_id after $MAX_RETRIES attempts.\nProgress: $(get_completed)/$TOTAL\n\nLog tail:\n$(tail -10 "$SCRIPT_DIR/caro.log")"
    fi
done

# Kill updater
kill $UPDATER_PID 2>/dev/null

completed=$(get_completed)
failed_ids=$(cat "$FAILED_FILE" 2>/dev/null | tr '\n' ' ' | xargs)
failed_count=$(get_failed_count)

if [ -f "$HALT_FILE" ]; then
    halt_id=$(cat "$HALT_FILE")
    echo ""
    echo "══════════════════════════════════════════════════════"
    echo "  BATCH STOPPED — usage limit hit on ARVO $halt_id"
    echo "══════════════════════════════════════════════════════"
    print_failed_and_remaining
    log "BATCH STOPPED (usage limit): $completed done, $failed_count failed"
    notify "CARO STOPPED — Usage Limit ($completed/$TOTAL)" \
        "Batch stopped due to usage limit on ARVO $halt_id.\n\nCompleted: $completed/$TOTAL\nFailed IDs: ${failed_ids:-none}\n\nRestart caro_monitor.sh after limit resets."
else
    echo ""
    echo "  FAILED IDs: ${failed_ids:-none}"
    echo ""
    log "BATCH COMPLETE: $completed/$TOTAL succeeded, $failed_count failed"
    notify "CARO Batch COMPLETE ($completed/$TOTAL)" \
        "Finished.\n\nSucceeded: $completed/$TOTAL\nFailed IDs: ${failed_ids:-none}\n\nResults in arvo_loc_runs.db"
fi

# Cleanup temp files
rm -f "$COUNT_FILE" "$FAILED_FILE" "$HALT_FILE"
