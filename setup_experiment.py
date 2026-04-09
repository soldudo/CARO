#!/usr/bin/env python3
"""
CARO Experiment Setup — interactive CLI/TUI
"""
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

DIR           = Path(__file__).parent
DB            = DIR / 'arvo_loc_runs.db' ## this should be possible to dynamically chagne 
CONFIG        = DIR / 'config' / 'experiment_setup.json'
MONITOR       = DIR / 'caro_monitor.sh'
NOTIFY_CONFIG = DIR / 'config' / 'notify_config.json'
# ── ANSI colours ───────────────────────────────────────────────────────────────
R='\033[0m'; B='\033[1m'; DIM='\033[2m'
CY='\033[96m'; GR='\033[92m'; YL='\033[93m'; RD='\033[91m'; MG='\033[95m'

def c(color, text): return f"{color}{text}{R}"
def header(title):
    w = 56
    print(f"\n{CY}{'─'*w}{R}")
    print(f"{B}{CY}  {title}{R}")
    print(f"{CY}{'─'*w}{R}")

def prompt(msg, default=None):
    hint = f" [{c(DIM, str(default))}]" if default is not None else ""
    val = input(f"  {CY}›{R} {msg}{hint}: ").strip()
    return val if val else default

def confirm(msg):
    return (prompt(f"{msg} (y/n)", "y") or "y").lower() == 'y'

from locked_ids import (git_sync_pull, get_synced_ids, get_local_claimed,
                        save_local_claimed, release_claimed_ids, push_claimed_ids)

# ── Notification helpers ───────────────────────────────────────────────────────
def load_notify_cfg():
    if NOTIFY_CONFIG.exists():
        return json.loads(NOTIFY_CONFIG.read_text())
    return {"method": "ntfy", "ntfy": {"url": "https://ntfy.sh", "topic": ""}}

def save_notify_cfg(cfg):
    NOTIFY_CONFIG.write_text(json.dumps(cfg, indent=4))

def ntfy_channel_str():
    cfg = load_notify_cfg()
    if cfg.get('method') == 'ntfy':
        url   = cfg['ntfy'].get('url', 'https://ntfy.sh').rstrip('/')
        topic = cfg['ntfy'].get('topic', '?')
        return f"{url}/{topic}"
    else:
        return f"smtp → {cfg.get('smtp',{}).get('recipient','?')}"

def send_test_notification():
    result = subprocess.run(
        ['python3', str(DIR / 'send_notification.py'), 'CARO Test', 'Test from CARO setup.'],
        capture_output=True, text=True, cwd=str(DIR)
    )
    if result.returncode == 0:
        print(c(GR, f"\n  ✓ {result.stdout.strip()}"))
    else:
        print(c(RD, f"\n  ✗ Failed:\n  {result.stderr.strip()}"))

# ── DB helpers ────────────────────────────────────────────────────────────────
def get_conn():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def get_already_run():
    with get_conn() as conn:
        rows = conn.execute("SELECT DISTINCT vuln_id FROM runs").fetchall()
    return {r['vuln_id'] for r in rows}

def get_projects():
    with get_conn() as conn:
        rows = conn.execute("SELECT DISTINCT project FROM arvo ORDER BY project").fetchall()
    return [r['project'] for r in rows]

def get_vulns(projects, exclude_ids):
    placeholders = ','.join('?' * len(projects))
    q = f"SELECT localId, project, crash_type FROM arvo WHERE project IN ({placeholders})"
    params = list(projects)
    if exclude_ids:
        ep = ','.join('?' * len(exclude_ids))
        q += f" AND localId NOT IN ({ep})"
        params += list(exclude_ids)
    q += " ORDER BY project, localId"
    with get_conn() as conn:
        return conn.execute(q, params).fetchall()

def run_summary():
    with get_conn() as conn:
        total  = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        unique = conn.execute("SELECT COUNT(DISTINCT vuln_id) FROM runs").fetchone()[0]
        cost   = conn.execute("SELECT ROUND(SUM(total_cost_usd),4) FROM runs").fetchone()[0] or 0
        events = conn.execute("SELECT COUNT(*) FROM run_events").fetchone()[0]
    return total, unique, cost, events

# ── Write helpers ──────────────────────────────────────────────────────────────
def save_monitor_ids(ids):
    text = MONITOR.read_text()
    ids_line = 'ARVO_IDS=(\n'
    for i, id_ in enumerate(ids):
        ids_line += f'    {id_}'
        ids_line += '\n' if (i+1) % 6 == 0 else ' '
    ids_line += '\n)'
    new_text = re.sub(r'ARVO_IDS=\(.*?\)', ids_line, text, flags=re.DOTALL)
    MONITOR.write_text(new_text)

# ── Re-auth ───────────────────────────────────────────────────────────────────
def reauth_claude():
    header("Re-authenticate Claude")

    if not docker_running('rootainer'):
        print(c(RD, "\n  ✗ rootainer is not running. Start it first via [6] First-time setup."))
        return

    # Check current auth state
    print(f"\n  {c(DIM,'Checking current auth state in rootainer...')} ", end='', flush=True)
    r = subprocess.run(
        ['docker', 'exec', 'rootainer', 'claude', '-p', 'hi', '--output-format', 'json'],
        capture_output=True, text=True, timeout=30
    )
    auth_ok = False
    if r.returncode == 0:
        try:
            import json as _json
            events = _json.loads(r.stdout)
            if isinstance(events, list):
                for e in events:
                    if isinstance(e, dict) and e.get('type') == 'result':
                        auth_ok = not e.get('is_error', True)
                        break
        except Exception:
            auth_ok = True  # non-JSON but exit 0 — treat as ok
    print(c(GR, '✓ authenticated') if auth_ok else c(RD, '✗ not authenticated / expired'))

    if not auth_ok:
        print(f"\n  {c(YL,'⚠')} Claude credentials in rootainer are expired or invalid.")
        print(f"  Open a shell, run {c(CY,'claude')} and follow the OAuth flow:")
        if confirm("  Open interactive shell in rootainer now?"):
            subprocess.run(['docker', 'exec', '-it', 'rootainer', 'bash'])
            print(f"  {c(DIM,'(returned from shell)')}")
    elif not confirm("\n  Auth looks fine. Re-authenticate anyway?"):
        pass
    else:
        if confirm("  Open interactive shell in rootainer to re-authenticate?"):
            subprocess.run(['docker', 'exec', '-it', 'rootainer', 'bash'])
            print(f"  {c(DIM,'(returned from shell)')}")

    print(c(GR, "\n  ✓ Claude re-authentication complete."))

# ── Diff tools ────────────────────────────────────────────────────────────────
def run_diff_tools():
    header("Diff Tools — Apply & Test a Patch")
    print(f"\n  Enter the {c(B,'patch run_id')} to apply and test its diff.")
    print(f"  {c(DIM,'This will spin up a container, apply the patch, compile, and run ARVO.')}\n")

    patch_run_id = prompt("patch run_id")
    if not patch_run_id:
        print(c(RD, "  No run_id provided."))
        return

    container_name = prompt("Container name for test", "diff_test")

    from queries import get_vuln_id, get_result_json
    from arvo_tools import standby_container, run_command

    vuln_result = get_vuln_id(patch_run_id)
    if not vuln_result:
        print(c(RD, f"  No run found for {patch_run_id}"))
        return
    vuln_id = vuln_result[0]
    print(f"  vuln_id: {c(CY, vuln_id)}")

    result_json_row = get_result_json(patch_run_id)
    if not result_json_row or not result_json_row[0]:
        print(c(RD, f"  No result_json found for {patch_run_id}"))
        return

    result_json = json.loads(result_json_row[0])
    patches = result_json.get('patches', [])
    if not patches:
        print(c(RD, "  No patches found in result_json."))
        return
    print(f"  Found {c(GR, len(patches))} patch(es)")

    # Write the unified diff file (inline — same logic as diff_tools.write_diff)
    patch_path = 'test.patch'
    with open(patch_path, 'w', encoding='utf-8') as f:
        for i, patch in enumerate(patches):
            diff_text = patch['diff']
            if not diff_text.endswith('\n'):
                diff_text += '\n'
            f.write(diff_text)
            if i < len(patches) - 1:
                f.write('\n')
    print(f"  {c(GR,'✓')} Wrote {patch_path}")

    print(f"\n  {c(DIM,'Starting standby container...')}")
    standby_container(container_name, vuln_id)

    pwd = run_command(['pwd'], container_name=container_name, stdout=subprocess.PIPE).stdout.strip()
    print(f"  {c(GR,'✓')} Container ready (pwd: {pwd})")

    print(f"\n  {c(B,'Applying patch...')}")
    patch_call = run_command(
        ['git', 'apply', '--verbose', '-C1', pwd + '/' + patch_path],
        container_name=container_name, check=False, stdout=subprocess.PIPE
    )
    if patch_call.returncode != 0:
        print(c(RD, f"  ✗ git apply failed"))
        if patch_call.stderr:
            print(f"    {patch_call.stderr.strip()}")
    else:
        print(f"  {c(GR,'✓')} Patch applied")

    print(f"\n  {c(B,'Compiling...')}")
    compile_result = run_command(['arvo', 'compile'], container_name=container_name, check=False, stdout=subprocess.PIPE)
    if compile_result.returncode != 0:
        print(c(RD, f"  ✗ Compilation failed"))
    else:
        print(f"  {c(GR,'✓')} Compiled")

    print(f"\n  {c(B,'Running ARVO...')}")
    arvo_result = run_command(['arvo'], container_name=container_name, check=False, stdout=subprocess.PIPE)
    if arvo_result.returncode != 0:
        print(c(RD, f"  ✗ ARVO failed (exit {arvo_result.returncode})"))
    else:
        print(f"  {c(GR,'✓')} ARVO passed")

    if arvo_result.stderr:
        print(f"\n  {c(DIM,'ARVO stderr:')}")
        for line in arvo_result.stderr.strip().splitlines()[:20]:
            print(f"    {line}")

# ── Worker / rootainer setup ───────────────────────────────────────────────────
def docker_running(name):
    r = subprocess.run(['docker', 'ps', '-q', '-f', f'name=^{name}$'],
                       capture_output=True, text=True)
    return bool(r.stdout.strip())

def docker_exists(name):
    r = subprocess.run(['docker', 'ps', '-aq', '-f', f'name=^{name}$'],
                       capture_output=True, text=True)
    return bool(r.stdout.strip())

def docker_image_exists(name):
    r = subprocess.run(['docker', 'images', '-q', name], capture_output=True, text=True)
    return bool(r.stdout.strip())

# ── First-time setup ───────────────────────────────────────────────────────────
def first_time_setup():
    header("First-Time Setup")

    image_ok     = docker_image_exists('claude_dind')
    container_ok = docker_running('rootainer')

    print(f"\n  {'Step':<6}  {'Task':<35}  Status")
    print(f"  {'─'*6}  {'─'*35}  {'─'*10}")
    print(f"  {'1':<6}  {'Build claude_dind image':<35}  {c(GR,'✓ done') if image_ok else c(YL,'needed')}")
    print(f"  {'2':<6}  {'Start rootainer container':<35}  {c(GR,'✓ running') if container_ok else c(YL,'needed')}")
    print(f"  {'3':<6}  {'Authenticate Claude inside rootainer':<35}  {c(DIM,'(use [7] Re-auth)')}")
    print()

    # Step 1 — build image
    if not image_ok:
        print(f"  {c(B,'Step 1 — Build claude_dind image')}")
        print(f"  {c(DIM,'Uses the Dockerfile in this repo.')}")
        if confirm("  Build now? (takes ~1 min)"):
            r = subprocess.run(['docker', 'build', '-t', 'claude_dind', str(DIR)],
                               cwd=str(DIR))
            if r.returncode != 0:
                print(c(RD, "\n  ✗ Build failed. Fix errors above and retry."))
                return
            image_ok = True
            print(c(GR, "  ✓ claude_dind image built"))
        else:
            print(f"\n  Run manually:  {c(CY, f'docker build -t claude_dind {DIR}')}")
            return
    else:
        print(f"  {c(GR,'✓')} claude_dind image already exists — skipping build")

    print()

    # Step 2 — start rootainer
    if not container_ok:
        print(f"  {c(B,'Step 2 — Start rootainer container')}")
        if docker_exists('rootainer'):
            print(f"  {c(YL,'⚠')} Container exists but is stopped. Restarting...")
            r = subprocess.run(['docker', 'start', 'rootainer'], capture_output=True, text=True)
        else:
            print(f"  {c(DIM,'Creating and starting rootainer...')}")
            r = subprocess.run([
                'docker', 'run', '--privileged', '--security-opt', 'label=disable',
                '--name', 'rootainer', '-d', 'claude_dind'
            ], capture_output=True, text=True)
        if r.returncode != 0:
            print(c(RD, f"  ✗ Failed: {r.stderr.strip()}"))
            return
        print(c(GR, "  ✓ rootainer is running"))
    else:
        print(f"  {c(GR,'✓')} rootainer already running — skipping")

    print()
    print(c(GR, "  ✓ Prerequisites ready."))
    print(f"  Next: {c(CY,'[7] Re-authenticate Claude')} if needed, then {c(CY,'[1] Setup new batch')}.")

# ── Notification settings ─────────────────────────────────────────────────────
def setup_notifications():
    header("Notification Settings  (ntfy.sh only)")
    cfg = load_notify_cfg()
    ntfy = cfg.setdefault('ntfy', {'url': 'https://ntfy.sh', 'topic': ''})
    cfg['method'] = 'ntfy'  # enforce ntfy only

    print(f"\n  Current channel: {c(YL, ntfy_channel_str())}")
    print(f"\n  {c(B,'Options:')}")
    print(f"    {c(CY,'[1]')} Change ntfy topic / server")
    print(f"    {c(CY,'[t]')} Send test notification")
    print(f"    {c(CY,'[b]')} Back")

    choice = prompt("").lower()

    if choice == '1':
        topic = prompt("ntfy topic", ntfy.get('topic', 'caro-kenan-uic'))
        url   = prompt("ntfy server", ntfy.get('url', 'https://ntfy.sh'))
        cfg['ntfy']['topic'] = topic
        cfg['ntfy']['url']   = url
        save_notify_cfg(cfg)
        print(c(GR, f"\n  ✓ Channel set to {url.rstrip('/')}/{topic}"))
        print(f"  Subscribe to {c(YL, topic)} in the ntfy app.")
    elif choice == 't':
        send_test_notification()

# ── Views ──────────────────────────────────────────────────────────────────────
def view_runs():
    header("Existing Runs")
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT r.run_id, r.vuln_id, a.project, r.num_turns,
                   r.total_cost_usd, r.result_type, r.timestamp
            FROM runs r LEFT JOIN arvo a ON r.vuln_id = a.localId
            ORDER BY r.timestamp DESC LIMIT 60
        """).fetchall()
    print(f"\n  {'RUN ID':<42} {'VULN':>11}  {'PROJECT':<10} {'TURNS':>5}  {'COST':>8}  RESULT")
    print(f"  {'─'*42} {'─'*11}  {'─'*10} {'─'*5}  {'─'*8}  {'─'*8}")
    for r in rows:
        cost_str = f"${r['total_cost_usd']:.4f}" if r['total_cost_usd'] else c(DIM, "   $0.00")
        res_col  = GR if r['result_type'] == 'success' else RD
        print(f"  {c(DIM,r['run_id']):<51} {r['vuln_id']:>11}  {(r['project'] or '?'):<10} "
              f"{(r['num_turns'] or 0):>5}  {cost_str:>8}  {c(res_col, r['result_type'] or '?')}")
    print()

def view_db_summary():
    total, unique, cost, events = run_summary()
    already = get_already_run()
    header("DB Summary")
    print(f"\n  {c(B,'Total runs')}      : {c(GR, total)}")
    print(f"  {c(B,'Unique vulns')}    : {c(GR, unique)}")
    print(f"  {c(B,'Total cost')}      : {c(YL, f'${cost:.4f}')}")
    print(f"  {c(B,'Total events')}    : {c(GR, events)}")
    print(f"\n  {c(B,'Already-run IDs')} ({len(already)}):")
    for i, vid in enumerate(sorted(already)):
        print(f"  {c(CY, vid)}", end='\n' if (i+1) % 8 == 0 else '')
    print('\n')

# ── ID selection helpers ──────────────────────────────────────────────────────

def toggle_id(vid, chosen_ids, pool_by_id):
    """Toggle a single ARVO ID in/out of chosen_ids. Prints feedback."""
    if vid not in pool_by_id:
        print(f"    {c(RD,'✗')} {vid} not in pool (already run, claimed, or filtered out)")
        return
    if vid in chosen_ids:
        chosen_ids.discard(vid)
        print(f"    {c(YL,'–')} Removed {vid}")
    else:
        chosen_ids.add(vid)
        r = pool_by_id[vid]
        print(f"    {c(GR,'✓')} {vid}  {r['project']}  {r['crash_type'][:40]}")

def search_and_toggle(chosen_ids, pool_by_id):
    """Prompt for ARVO IDs (comma-separated) and toggle each one."""
    raw = prompt("ARVO ID(s), comma-separated")
    if not raw:
        return
    for tok in raw.split(','):
        tok = tok.strip()
        if tok.isdigit():
            toggle_id(int(tok), chosen_ids, pool_by_id)

def select_by_search(pool):
    """Search-only selection mode: enter IDs until done."""
    pool_by_id = {r['localId']: r for r in pool}
    chosen_ids = set()
    print(f"\n  {c(B,'Search by ARVO ID')}  (pool: {len(pool)})")
    print(f"  Enter IDs (comma-separated), or {c(CY,'d')} when finished.\n")
    while True:
        cmd = prompt("ID(s)")
        if not cmd or cmd.strip().lower() == 'd':
            break
        for tok in cmd.split(','):
            tok = tok.strip()
            if tok.isdigit():
                toggle_id(int(tok), chosen_ids, pool_by_id)
        if chosen_ids:
            print(f"\n  {c(DIM, f'Selected so far: {len(chosen_ids)}')}")
    return [pool_by_id[vid] for vid in chosen_ids if vid in pool_by_id]

def select_by_browse(pool):
    """Paginated list with toggle-by-number and search."""
    pool_list = list(pool)
    pool_by_id = {r['localId']: r for r in pool_list}
    chosen_ids = set()
    PAGE, page = 30, 0

    while True:
        start = page * PAGE
        chunk = pool_list[start:start + PAGE]
        print(f"\n  {c(B, f'Page {page+1} — {start+1}–{start+len(chunk)} of {len(pool_list)}')}")
        print(f"  {'':5} {'ID':>11}  {'PROJECT':<10}  {'CRASH TYPE':<40}")
        print(f"  {'─'*5} {'─'*11}  {'─'*10}  {'─'*40}")
        for i, r in enumerate(chunk):
            mark = c(GR, ' ✓') if r['localId'] in chosen_ids else '  '
            print(f"  {mark}{c(CY,f'[{start+i+1}]'):<14} {r['localId']:>11}  {r['project']:<10}  "
                  f"{r['crash_type'][:40]}")
        print(f"\n  Toggle numbers, {c(CY,'s')}earch by ID, {c(CY,'n')}ext, {c(CY,'p')}rev, {c(CY,'d')}one")
        cmd = prompt("").lower()

        if cmd == 'n' and start + PAGE < len(pool_list):
            page += 1
        elif cmd == 'p' and page > 0:
            page -= 1
        elif cmd == 'd':
            break
        elif cmd == 's':
            search_and_toggle(chosen_ids, pool_by_id)
        else:
            for tok in cmd.split(','):
                tok = tok.strip()
                if tok.isdigit():
                    idx = int(tok) - 1
                    if 0 <= idx < len(pool_list):
                        vid = pool_list[idx]['localId']
                        toggle_id(vid, chosen_ids, pool_by_id)

    return [r for r in pool_list if r['localId'] in chosen_ids]

# ── Batch setup ────────────────────────────────────────────────────────────────

def sync_claimed_ids(already_run):
    """Sync with GitHub and release stale claims. Returns current synced set."""
    print(f"\n  {c(DIM,'Syncing claimed IDs from GitHub...')} ", end='', flush=True)
    pull_ok, _ = git_sync_pull()
    synced_ids = get_synced_ids()
    if pull_ok:
        new_from_remote = synced_ids - already_run
        print(c(GR, f'✓  ({len(synced_ids)} total claimed'
                    + (f', {len(new_from_remote)} new from other machines)' if new_from_remote else ')')))
    else:
        print(c(YL, f'⚠  Pull failed — working with local data only'))

    # Offer to release locally claimed but unrun IDs
    local_claimed = get_local_claimed()
    unrun_claimed = local_claimed - already_run
    if unrun_claimed:
        print(f"\n  {c(YL,'⚠')} {len(unrun_claimed)} IDs claimed by this machine but not yet run:")
        print(f"  {c(DIM, ', '.join(str(i) for i in sorted(unrun_claimed)))}")
        if confirm("  Release them so other machines can pick them?"):
            ok, msg = release_claimed_ids(list(unrun_claimed))
            if ok:
                save_local_claimed(local_claimed - unrun_claimed)
                synced_ids = get_synced_ids()
                print(c(GR, f"  ✓ Released {len(unrun_claimed)} IDs"))
            else:
                print(c(YL, f"  ⚠ Release failed: {msg}"))
    return synced_ids

def pick_projects():
    """Let the user choose which projects to draw vulnerabilities from."""
    all_projects = get_projects()
    print(f"\n  {c(B,'Available projects:')}  (number, comma-list of names, or a for all)")
    for i, p in enumerate(all_projects, 1):
        print(f"    {c(CY,f'[{i}]')} {p}")
    print(f"    {c(CY,'[a]')} All")

    sel = prompt("Select", "a")
    if sel.lower() == 'a':
        return all_projects

    chosen = []
    for tok in sel.split(','):
        tok = tok.strip()
        if tok.isdigit():
            idx = int(tok) - 1
            if 0 <= idx < len(all_projects):
                chosen.append(all_projects[idx])
        else:
            match = next((p for p in all_projects if p.lower() == tok.lower()), None)
            if match:
                chosen.append(match)
    return chosen or all_projects

def pick_run_mode():
    """Let the user choose loc, patch, or both. Returns (is_loc, is_patch, loc_run_id)."""
    cur_cfg = json.loads(CONFIG.read_text())
    cur_loc   = cur_cfg.get('is_loc_mode', True)
    cur_patch = cur_cfg.get('is_patch_mode', False)
    if cur_loc and cur_patch:   cur_mode_str = 'both'
    elif cur_patch:             cur_mode_str = 'patch only'
    else:                       cur_mode_str = 'loc only'

    print(f"\n  {c(B,'Run mode')}  {c(DIM, f'(currently: {cur_mode_str})')}")
    print(f"    {c(CY,'[1]')} Localization only")
    print(f"    {c(CY,'[2]')} Patch only  {c(DIM,'(requires a loc_run_id from a previous run)')}")
    print(f"    {c(CY,'[3]')} Both — localization then patch")
    choice = prompt("Mode", "1" if not cur_patch else ("2" if not cur_loc else "3"))

    is_loc   = choice != '2'
    is_patch = choice in ('2', '3')
    loc_run_id = ''

    if choice == '2':
        loc_run_id = prompt("  loc_run_id from previous run", cur_cfg.get('loc_run_id', '')) or ''
        if not loc_run_id:
            print(c(RD, "  ✗ loc_run_id required for patch-only mode."))
            return None

    mode_label = {'1': c(GR, 'Localization only'),
                  '2': c(YL, 'Patch only'),
                  '3': c(GR, 'Both (loc + patch)')}.get(choice, '')
    print(f"  Mode: {mode_label}")
    if loc_run_id:
        print(f"  loc_run_id: {c(CY, loc_run_id)}")
    return is_loc, is_patch, loc_run_id

def save_and_launch(selected, run_mode):
    """Write config + monitor IDs, claim on GitHub, optionally launch."""
    is_loc, is_patch, loc_run_id = run_mode

    if not confirm("\n  Save and update caro_monitor.sh?"):
        return

    # Update experiment config
    cur_cfg = json.loads(CONFIG.read_text())
    cur_cfg['is_loc_mode']  = is_loc
    cur_cfg['is_patch_mode'] = is_patch
    cur_cfg['loc_run_id']   = loc_run_id
    for old_key in ('patch_enabled', 'initial_prompt'):
        cur_cfg.pop(old_key, None)
    CONFIG.write_text(json.dumps(cur_cfg, indent=4))
    print(c(GR, f"  ✓ run mode saved to experiment_setup.json"))

    # Write IDs to monitor script
    ids = [r['localId'] for r in selected]
    save_monitor_ids(ids)
    print(c(GR, f"\n  ✓ {len(ids)} IDs written to caro_monitor.sh"))

    # Claim IDs on GitHub
    save_local_claimed(get_local_claimed() | set(ids))
    print(f"  {c(DIM,'Pushing claimed IDs to GitHub...')} ", end='', flush=True)
    push_ok, push_msg = push_claimed_ids(ids)
    if push_ok:
        print(c(GR, f'✓  ({len(ids)} IDs now blocked on remote)'))
    else:
        print(c(YL, f'⚠  Push failed — run `git push` manually to sync\n  {c(DIM, push_msg)}'))

    # Launch
    if confirm("  Launch caro_monitor.sh now?"):
        print(c(GR, "\n  Starting monitor (Ctrl+C to abort)...\n"))
        try:
            subprocess.run(['bash', str(MONITOR)], cwd=str(DIR))
        except KeyboardInterrupt:
            print(c(YL, "\n  Monitor interrupted."))
        print(f"\n  Monitor finished. Channel: {c(YL, ntfy_channel_str())}\n")
    else:
        print(f"\n  Run: {c(CY,'bash caro_monitor.sh')}\n")

def setup_batch():
    header("Setup New Experiment Batch")
    already_run = get_already_run()

    # ── Step 1: Sync claimed IDs ──────────────────────────────────────────────
    synced_ids = sync_claimed_ids(already_run)

    # ── Step 2: Filter pool ───────────────────────────────────────────────────
    exclude = confirm(f"Exclude {len(already_run)} already-run IDs?")
    chosen_projects = pick_projects()
    print(f"  {c(GR,'✓')} Projects: {', '.join(chosen_projects)}")

    exclude_ids = (already_run if exclude else set()) | synced_ids
    if synced_ids - already_run:
        print(f"  {c(DIM, f'+ {len(synced_ids - already_run)} IDs claimed by other machines excluded')}")
    pool = get_vulns(chosen_projects, exclude_ids)
    if not pool:
        print(c(RD, "\n  No vulnerabilities match filters."))
        return

    # ── Step 3: Select IDs ────────────────────────────────────────────────────
    print(f"\n  {c(B,'Selection mode:')}")
    print(f"    {c(CY,'[r]')} Random")
    print(f"    {c(CY,'[s]')} Search by ID")
    print(f"    {c(CY,'[m]')} Manual — browse & pick")
    mode = prompt("Mode", "r").lower()

    if mode == 'r':
        n = int(prompt(f"How many? (pool: {len(pool)})", "20"))
        selected = random.sample(list(pool), min(n, len(pool)))
    elif mode == 's':
        selected = select_by_search(list(pool))
    else:
        selected = select_by_browse(pool)

    if not selected:
        print(c(RD, "\n  Nothing selected."))
        return

    # ── Step 4: Preview ───────────────────────────────────────────────────────
    header(f"Selected — {len(selected)} experiments")
    by_proj = {}
    for r in selected:
        by_proj.setdefault(r['project'], []).append(r)
    for proj, items in sorted(by_proj.items()):
        print(f"\n  {c(B, proj)} ({len(items)})")
        for r in items:
            print(f"    {r['localId']:>11}  {r['crash_type'][:50]}")
    print(f"\n  Channel : {c(YL, ntfy_channel_str())}")

    # ── Step 5: Run mode ──────────────────────────────────────────────────────
    run_mode = pick_run_mode()
    if run_mode is None:
        return

    # ── Step 6: Save & launch ─────────────────────────────────────────────────
    save_and_launch(selected, run_mode)

# ── Guided setup ──────────────────────────────────────────────────────────────
def guided_setup():
    """Step-by-step wizard: prerequisites → notifications → batch → launch."""
    header("Guided Setup  (step-by-step)")

    # ── Step 1: Prerequisites ─────────────────────────────────────────────────
    if not docker_image_exists('claude_dind') or not docker_running('rootainer'):
        print(f"\n  {c(B,'Step 1/3 — Prerequisites (first-time setup)')}")
        first_time_setup()
        if not docker_running('rootainer'):
            print(c(RD, "\n  ✗ rootainer not running — cannot continue."))
            return
    else:
        print(f"\n  {c(GR,'✓')} {c(B,'Step 1/3')} — rootainer running")

    # ── Step 2: Notifications ─────────────────────────────────────────────────
    print(f"\n  {c(B,'Step 2/3 — Notifications')}")
    topic = load_notify_cfg().get('ntfy', {}).get('topic', '')
    if topic:
        print(f"  {c(GR,'✓')} Channel: {c(YL, ntfy_channel_str())}")
        if confirm("  Send a test notification?"):
            send_test_notification()
    else:
        print(f"  {c(YL,'⚠')} No ntfy topic configured.")
        if confirm("  Configure notifications now?"):
            setup_notifications()

    # ── Step 3: Batch selection ───────────────────────────────────────────────
    print(f"\n  {c(B,'Step 3/3 — Experiment batch')}")
    setup_batch()

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    os.system('clear')
    total, unique, cost, events = run_summary()
    already = len(get_already_run())
    channel = ntfy_channel_str()

    print(f"\n{B}{CY}  ╔════════════════════════════════════════════╗")
    print(f"  ║   CARO — Experiment Setup                  ║")
    print(f"  ╚════════════════════════════════════════════╝{R}")
    synced_count = len(get_synced_ids())
    print(f"\n  {c(DIM,'Runs:')} {c(GR,total)}  "
          f"{c(DIM,'Vulns:')} {c(GR,unique)}  "
          f"{c(DIM,'Cost:')} {c(YL,f'${cost:.2f}')}  "
          f"{c(DIM,'Synced claimed:')} {c(YL,synced_count)}")
    print(f"  {c(DIM,'Channel:')} {c(YL, channel)}")

    while True:
        already = len(get_already_run())

        print(f"\n  {c(B,'Menu')}")
        print(f"    {c(GR,'[0]')} {c(B,'Guided setup')}  {c(DIM,'← start here')}")
        print(f"    {c(CY,'[1]')} Setup new batch")
        print(f"    {c(CY,'[2]')} View existing runs")
        print(f"    {c(CY,'[3]')} DB summary  ({already} already-run IDs)")
        print(f"    {c(CY,'[4]')} Notification settings  [{c(YL, ntfy_channel_str())}]")
        print(f"    {c(CY,'[5]')} First-time setup  {c(DIM,'(build image, start rootainer)')}")
        print(f"    {c(CY,'[6]')} Re-authenticate Claude  {c(DIM,'(fix expired credentials)')}")
        print(f"    {c(CY,'[7]')} Diff tools  {c(DIM,'(apply & test a patch from a run)')}")
        print(f"    {c(CY,'[q]')} Quit")
        choice = prompt("", "0").lower()

        if choice == '0':   guided_setup()
        elif choice == '1': setup_batch()
        elif choice == '2': view_runs()
        elif choice == '3': view_db_summary()
        elif choice == '4': setup_notifications()
        elif choice == '5': first_time_setup()
        elif choice == '6': reauth_claude()
        elif choice == '7': run_diff_tools()
        elif choice == 'q':
            print(f"\n  {c(DIM,'Bye.')}\n")
            sys.exit(0)

if __name__ == '__main__':
    main()
