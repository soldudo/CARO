#!/bin/bash
# CARO Parallel Batch Monitor
# Runs experiments across N_WORKERS rootainer instances simultaneously.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MONITOR_LOG="$SCRIPT_DIR/monitor.log"
MAX_RETRIES=3
EMAIL_INTERVAL=1800   # 30 minutes
N_WORKERS=4

# ── IDs to run (updated by setup_experiment.py) ───────────────────────────────
ARVO_IDS=(
    42537773 42485228 42476260 42529309 42520086 42475813
    42531092 42470291 42525192 42510687 42537493 42533950
    42534863 393404264 42487777 42482611 42502936 42480500
    42507241 42493786 42526340 42513382 42486167 42485988
    42504267 42522715 42527937 42492416 42531502 42521453
)

TOTAL=${#ARVO_IDS[@]}

# ── Shared state files ─────────────────────────────────────────────────────────
QUEUE_FILE="$SCRIPT_DIR/.worker_queue"
QUEUE_LOCK="$SCRIPT_DIR/.queue.lock"
COUNT_FILE="$SCRIPT_DIR/.completed_count"
FAILED_FILE="$SCRIPT_DIR/.failed_ids"
HALT_FILE="$SCRIPT_DIR/.halt"

# ── Helpers ───────────────────────────────────────────────────────────────────
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$MONITOR_LOG"
}

notify() {
    python3 "$SCRIPT_DIR/send_email.py" "$1" "$2" 2>>"$MONITOR_LOG" && \
        log "  ntfy sent: $1" || log "  ntfy FAILED: $1"
}

ntfy_topic() {
    python3 -c "
import json
try:
    cfg=json.load(open('$SCRIPT_DIR/notify_config.json'))
    m=cfg.get('method','ntfy')
    if m=='ntfy': print('ntfy: ' + cfg['ntfy']['url'].rstrip('/') + '/' + cfg['ntfy']['topic'])
    else: print('smtp: ' + cfg['smtp'].get('recipient','?'))
except: print('(notify_config.json not found)')
"
}

next_id() {
    # Atomically pop the first line from the queue file
    (
        flock -x 9
        id=$(head -1 "$QUEUE_FILE" 2>/dev/null)
        if [ -n "$id" ]; then
            sed -i '1d' "$QUEUE_FILE"
            echo "$id"
        fi
    ) 9>"$QUEUE_LOCK"
}

inc_completed() {
    (
        flock -x 9
        count=$(( $(cat "$COUNT_FILE" 2>/dev/null || echo 0) + 1 ))
        echo $count > "$COUNT_FILE"
        echo $count
    ) 9>"$SCRIPT_DIR/.count.lock"
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
    remaining_ids=$(grep -v '^$' "$QUEUE_FILE" 2>/dev/null | tr '\n' ' ' | xargs)
    echo ""
    echo "  FAILED IDs (exhausted retries):"
    echo "  ${failed_ids:-none}"
    echo ""
    echo "  REMAINING IDs (not yet run — abandoned):"
    echo "  ${remaining_ids:-none}"
    echo ""
}

signal_halt() {
    local arvo_id=$1
    local wid=$2
    # Only the first caller creates the halt file (atomic check)
    [ -f "$HALT_FILE" ] && return
    echo "$arvo_id" > "$HALT_FILE"

    echo ""
    echo "══════════════════════════════════════════════════════"
    echo "  USAGE LIMIT HIT — stopping all workers"
    echo "  Triggered by ARVO $arvo_id (worker $wid)"
    echo "══════════════════════════════════════════════════════"
    print_failed_and_remaining

    local failed_ids remaining_ids
    failed_ids=$(cat "$FAILED_FILE" 2>/dev/null | tr '\n' ' ' | xargs)
    remaining_ids=$(grep -v '^$' "$QUEUE_FILE" 2>/dev/null | tr '\n' ' ' | xargs)
    notify "CARO HALTED — Usage Limit Hit" \
        "Worker $wid hit the usage limit on ARVO $arvo_id.\n\nFailed IDs: ${failed_ids:-none}\nRemaining (not run): ${remaining_ids:-none}\n\nRestart after limit resets."
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

# ── Worker ────────────────────────────────────────────────────────────────────
worker() {
    local wid=$1
    local container="rootainer-$wid"
    local wlog="$SCRIPT_DIR/caro_w${wid}.log"
    local wcfg="$SCRIPT_DIR/experiment_setup_w${wid}.json"

    log "[W$wid/$container] Worker started"

    while true; do
        # Check halt flag before picking next ID
        if [ -f "$HALT_FILE" ]; then
            log "[W$wid] Halt signal detected — exiting"
            break
        fi

        arvo_id=$(next_id)
        [ -z "$arvo_id" ] && { log "[W$wid] Queue empty — worker done."; break; }

        log "[W$wid] ── ARVO $arvo_id ──"
        set_arvo_id "$arvo_id" "$wcfg"

        success=false
        for attempt in $(seq 1 $MAX_RETRIES); do
            # Check halt flag before each attempt too
            [ -f "$HALT_FILE" ] && break

            > "$wlog"
            log "[W$wid] Attempt $attempt/$MAX_RETRIES for $arvo_id"

            cd "$SCRIPT_DIR"
            # Redirect all output to wlog so check_quota_error can scan it
            python3 caro.py --config "$wcfg" >> "$wlog" 2>&1
            EXIT_CODE=$?

            if [ $EXIT_CODE -eq 0 ]; then
                success=true
                log "[W$wid] SUCCESS: $arvo_id"
                break
            fi

            if check_quota_error "$wlog"; then
                log "[W$wid] USAGE LIMIT detected on $arvo_id — halting all workers"
                echo "$arvo_id" >> "$FAILED_FILE"
                signal_halt "$arvo_id" "$wid"
                exit 2
            fi

            log "[W$wid] FAILED (exit $EXIT_CODE) attempt $attempt for $arvo_id"
            [ $attempt -lt $MAX_RETRIES ] && sleep 30
        done

        if $success; then
            completed=$(inc_completed)
            notify "CARO Done [$container]: $arvo_id ($completed/$TOTAL)" \
                "Worker $wid ($container) completed ARVO $arvo_id.\nProgress: $completed/$TOTAL\n\nLog tail:\n$(tail -20 $wlog)"
        else
            echo "$arvo_id" >> "$FAILED_FILE"
            log "[W$wid] GAVE UP on $arvo_id after $MAX_RETRIES attempts"
            notify "CARO FAILED [$container]: $arvo_id" \
                "Worker $wid failed ARVO $arvo_id after $MAX_RETRIES attempts.\nProgress: $(get_completed)/$TOTAL\n\nLog tail:\n$(tail -10 $wlog)"
        fi
    done
}

# ── Periodic updater ──────────────────────────────────────────────────────────
updater() {
    while true; do
        sleep $EMAIL_INTERVAL
        completed=$(get_completed)
        failed=$(get_failed_count)
        remaining=$(( TOTAL - completed - failed ))
        status="Progress: $completed done / $failed failed / $remaining remaining (of $TOTAL)\n\n"
        for i in $(seq 0 $((N_WORKERS-1))); do
            wlog="$SCRIPT_DIR/caro_w${i}.log"
            last=$(tail -2 "$wlog" 2>/dev/null | tr '\n' ' ')
            status+="W$i (rootainer-$i): $last\n"
        done
        notify "CARO Update: $completed/$TOTAL done" "$status"
    done
}

# ── Main ──────────────────────────────────────────────────────────────────────
log "=========================================="
log " CARO Parallel Monitor  —  $N_WORKERS workers"
log " Total IDs : $TOTAL"
log " Channel   : $(ntfy_topic)"
log "=========================================="

# Print channel to screen
echo ""
echo "  Notifications → $(ntfy_topic)"
echo ""

# Init shared state — ensure clean slate
rm -f "$HALT_FILE"
printf '%s\n' "${ARVO_IDS[@]}" > "$QUEUE_FILE"
echo 0 > "$COUNT_FILE"
> "$FAILED_FILE"

notify "CARO Batch Started (0/$TOTAL)" \
    "$N_WORKERS workers starting on $TOTAL experiments.\n\nIDs: ${ARVO_IDS[*]}\nChannel: $(ntfy_topic)"

# Start periodic updater in background
updater &
UPDATER_PID=$!

# Start workers
worker_pids=()
for i in $(seq 0 $((N_WORKERS-1))); do
    worker $i &
    worker_pids+=($!)
    log "  Launched worker $i (PID ${worker_pids[-1]}) on rootainer-$i"
done

# Wait for all workers
for pid in "${worker_pids[@]}"; do
    wait $pid
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
        "All $N_WORKERS workers finished.\n\nSucceeded: $completed/$TOTAL\nFailed IDs: ${failed_ids:-none}\n\nResults in arvo_loc_runs.db"
fi

# Cleanup temp files
rm -f "$QUEUE_FILE" "$QUEUE_LOCK" "$COUNT_FILE" "$FAILED_FILE" "$HALT_FILE" \
      "$SCRIPT_DIR/.count.lock" "$SCRIPT_DIR/.queue.lock"
