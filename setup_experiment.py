#!/usr/bin/env python3
"""
CARO Experiment Setup — interactive CLI
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
DB            = DIR / 'arvo_loc_runs.db'
CONFIG        = DIR / 'experiment_setup.json'
MONITOR       = DIR / 'caro_monitor.sh'
NOTIFY_CONFIG = DIR / 'notify_config.json'
SYNCED_FILE   = DIR / 'synced_ids.json'

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

# ── GitHub sync helpers ────────────────────────────────────────────────────────
def git_sync_pull():
    """Pull latest from remote. Returns (success, message)."""
    r = subprocess.run(
        ['git', 'pull', '--rebase', '--autostash'],
        cwd=str(DIR), capture_output=True, text=True
    )
    return r.returncode == 0, (r.stdout + r.stderr).strip()

def get_synced_ids():
    """Return the set of IDs already claimed across all machines."""
    if not SYNCED_FILE.exists():
        return set()
    try:
        return set(json.loads(SYNCED_FILE.read_text()).get('claimed', []))
    except Exception:
        return set()

def push_claimed_ids(new_ids: list, max_retries: int = 3):
    """Merge new_ids into synced_ids.json, commit and push. Returns (success, message)."""
    for _ in range(max_retries):
        subprocess.run(['git', 'pull', '--rebase', '--autostash'],
                       cwd=str(DIR), capture_output=True)
        combined = sorted(get_synced_ids() | set(new_ids))
        SYNCED_FILE.write_text(json.dumps({'claimed': combined}, indent=2) + '\n')
        subprocess.run(['git', 'add', str(SYNCED_FILE)], cwd=str(DIR), capture_output=True)
        subprocess.run(
            ['git', 'commit', '-m', f'chore: claim {len(new_ids)} ARVO IDs'],
            cwd=str(DIR), capture_output=True
        )
        r = subprocess.run(['git', 'push'], cwd=str(DIR), capture_output=True, text=True)
        if r.returncode == 0:
            return True, r.stdout.strip()
    return False, f'Push failed after {max_retries} attempts'

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
        ['python3', str(DIR / 'send_email.py'), 'CARO Test', 'Test from CARO setup.'],
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

def get_vulns(projects, exclude_ids, crash_log_filter):
    placeholders = ','.join('?' * len(projects))
    q = f"SELECT localId, project, crash_type, on_crash_log FROM arvo WHERE project IN ({placeholders})"
    params = list(projects)
    if exclude_ids:
        ep = ','.join('?' * len(exclude_ids))
        q += f" AND localId NOT IN ({ep})"
        params += list(exclude_ids)
    if crash_log_filter == '1':
        q += " AND on_crash_log = 1"
    elif crash_log_filter == '0':
        q += " AND on_crash_log = 0"
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

def save_monitor_workers(n):
    text = MONITOR.read_text()
    new_text = re.sub(r'N_WORKERS=\d+', f'N_WORKERS={n}', text)
    MONITOR.write_text(new_text)

def get_monitor_workers():
    text = MONITOR.read_text()
    m = re.search(r'N_WORKERS=(\d+)', text)
    return int(m.group(1)) if m else 1

def make_worker_config(worker_id):
    """Create experiment_setup_w{id}.json for a given worker."""
    cfg = json.loads(CONFIG.read_text())
    cfg['container_name'] = f'rootainer-{worker_id}'
    wpath = DIR / f'experiment_setup_w{worker_id}.json'
    wpath.write_text(json.dumps(cfg, indent=4))
    return wpath

# ── Worker / rootainer setup ───────────────────────────────────────────────────
def docker_running(name):
    r = subprocess.run(['docker', 'ps', '-q', '-f', f'name=^{name}$'],
                       capture_output=True, text=True)
    return bool(r.stdout.strip())

def docker_exists(name):
    r = subprocess.run(['docker', 'ps', '-aq', '-f', f'name=^{name}$'],
                       capture_output=True, text=True)
    return bool(r.stdout.strip())

def setup_workers():
    header("Worker / rootainer Setup")
    n_workers = get_monitor_workers()
    print(f"\n  Current N_WORKERS: {c(YL, n_workers)}")
    print(f"  Workers use containers: {c(CY, 'rootainer-0')}, {c(CY,'rootainer-1')}, ...\n")

    n = int(prompt("How many parallel workers? (1–4)", str(n_workers)))
    n = max(1, min(4, n))

    # Check base rootainer exists
    if not docker_exists('rootainer'):
        print(c(RD, "\n  ✗ 'rootainer' container not found. Build and start it first."))
        return

    # Commit rootainer to image (preserves Claude auth)
    print(f"\n  {c(DIM,'Committing rootainer → rootainer-auth image...')}")
    r = subprocess.run(['docker', 'commit', 'rootainer', 'rootainer-auth'],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(c(RD, f"  ✗ Commit failed: {r.stderr.strip()}"))
        return
    print(c(GR, "  ✓ rootainer-auth image created"))

    for i in range(n):
        name = f'rootainer-{i}'
        print(f"\n  Setting up {c(CY, name)}...")

        if docker_running(name):
            print(f"  {c(GR,'✓')} Already running")
        else:
            if docker_exists(name):
                subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
            r = subprocess.run(
                ['docker', 'run', '--privileged', '--name', name, '-d', 'rootainer-auth'],
                capture_output=True, text=True
            )
            if r.returncode == 0:
                print(f"  {c(GR,'✓')} Started")
            else:
                print(c(RD, f"  ✗ Failed to start: {r.stderr.strip()}"))
                continue

        # Copy agent files
        for fname in ['memory_safety_agent.md', 'memory_safety_skills.md']:
            src = DIR / fname
            if src.exists():
                subprocess.run(['docker', 'exec', name, 'mkdir', '-p', '/opt/agent'],
                               capture_output=True)
                subprocess.run(['docker', 'cp', str(src), f'{name}:/opt/agent/{fname}'],
                               capture_output=True)
        print(f"  {c(GR,'✓')} Agent files copied")

        # Write worker config
        make_worker_config(i)
        print(f"  {c(GR,'✓')} experiment_setup_w{i}.json created")

    # Update N_WORKERS in monitor
    save_monitor_workers(n)
    print(c(GR, f"\n  ✓ N_WORKERS set to {n} in caro_monitor.sh"))
    print(f"  {c(DIM,'Workers: ' + ', '.join(f'rootainer-{i}' for i in range(n)))}")

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

# ── Batch setup ────────────────────────────────────────────────────────────────
def setup_batch():
    header("Setup New Experiment Batch")
    n_workers = get_monitor_workers()
    already_run = get_already_run()

    # Sync with GitHub before picking to avoid duplicate runs across machines
    print(f"\n  {c(DIM,'Syncing claimed IDs from GitHub...')} ", end='', flush=True)
    pull_ok, pull_msg = git_sync_pull()
    synced_ids = get_synced_ids()
    if pull_ok:
        new_from_remote = synced_ids - already_run
        print(c(GR, f'✓  ({len(synced_ids)} total claimed'
                    + (f', {len(new_from_remote)} new from other machines)' if new_from_remote else ')')))
    else:
        print(c(YL, f'⚠  Pull failed — working with local data only'))

    # 1. Exclude already-run?
    exclude = confirm(f"Exclude {len(already_run)} already-run IDs?")

    # 2. Projects
    all_projects = get_projects()
    print(f"\n  {c(B,'Available projects:')}")
    for i, p in enumerate(all_projects, 1):
        print(f"    {c(CY,f'[{i}]')} {p}")
    print(f"    {c(CY,'[a]')} All")
    sel = prompt("Select (e.g. 1,3 or a)", "a")
    if sel.lower() == 'a':
        chosen_projects = all_projects
    else:
        idxs = [int(x.strip())-1 for x in sel.split(',') if x.strip().isdigit()]
        chosen_projects = [all_projects[i] for i in idxs if 0 <= i < len(all_projects)]
    print(f"  {c(GR,'✓')} Projects: {', '.join(chosen_projects)}")

    # 3. on_crash_log filter
    print(f"\n  {c(B,'on_crash_log filter:')}")
    print(f"    {c(CY,'[m]')} Mixed  {c(DIM,'← recommended')}")
    print(f"    {c(CY,'[1]')} Only on_crash_log = 1")
    print(f"    {c(CY,'[0]')} Only on_crash_log = 0")
    crash_filter = prompt("Filter", "m").lower()
    if crash_filter not in ('0', '1'):
        crash_filter = 'mixed'

    # 4. Random or manual
    print(f"\n  {c(B,'Selection mode:')}")
    print(f"    {c(CY,'[r]')} Random")
    print(f"    {c(CY,'[m]')} Manual — pick from list")
    mode = prompt("Mode", "r").lower()

    local_excluded = already_run if exclude else set()
    # Always exclude synced IDs (claimed by any machine, running or done)
    exclude_ids = local_excluded | synced_ids
    if synced_ids - already_run:
        print(f"  {c(DIM, f'+ {len(synced_ids - already_run)} IDs claimed by other machines also excluded')}")
    pool = get_vulns(chosen_projects, exclude_ids, crash_filter if crash_filter != 'mixed' else 'any')

    if not pool:
        print(c(RD, "\n  No vulnerabilities match filters."))
        return

    selected = []

    if mode == 'r':
        n = int(prompt(f"How many? (pool: {len(pool)})", "20"))
        if crash_filter == 'mixed':
            with_log    = [r for r in pool if r['on_crash_log'] == 1]
            without_log = [r for r in pool if r['on_crash_log'] == 0]
            half = n // 2
            sel1 = random.sample(with_log,    min(half, len(with_log)))
            sel0 = random.sample(without_log, min(n - len(sel1), len(without_log)))
            selected = sel1 + sel0
            random.shuffle(selected)
        else:
            selected = random.sample(list(pool), min(n, len(pool)))
    else:
        pool_list = list(pool)
        PAGE, page, chosen_ids = 30, 0, set()
        while True:
            start = page * PAGE
            chunk = pool_list[start:start+PAGE]
            print(f"\n  {c(B, f'Page {page+1} — {start+1}–{start+len(chunk)} of {len(pool_list)}')}")
            print(f"  {'':5} {'ID':>11}  {'PROJECT':<10}  {'CRASH TYPE':<35}  LOG")
            print(f"  {'─'*5} {'─'*11}  {'─'*10}  {'─'*35}  {'─'*3}")
            for i, r in enumerate(chunk):
                mark = c(GR, ' ✓') if r['localId'] in chosen_ids else '  '
                print(f"  {mark}{c(CY,f'[{start+i+1}]'):<14} {r['localId']:>11}  {r['project']:<10}  "
                      f"{r['crash_type'][:35]:<35}  {r['on_crash_log']}")
            print(f"\n  Toggle numbers, {c(CY,'[n]')}ext, {c(CY,'[p]')}rev, {c(CY,'[d]')}one")
            cmd = prompt("").lower()
            if cmd == 'n':
                if start + PAGE < len(pool_list): page += 1
            elif cmd == 'p':
                if page > 0: page -= 1
            elif cmd == 'd':
                break
            else:
                for tok in cmd.split(','):
                    tok = tok.strip()
                    if tok.isdigit():
                        idx = int(tok) - 1
                        if 0 <= idx < len(pool_list):
                            vid = pool_list[idx]['localId']
                            chosen_ids.discard(vid) if vid in chosen_ids else chosen_ids.add(vid)
        selected = [r for r in pool_list if r['localId'] in chosen_ids]

    if not selected:
        print(c(RD, "\n  Nothing selected."))
        return

    # Preview
    header(f"Selected — {len(selected)} experiments  ({n_workers} workers)")
    by_proj = {}
    for r in selected:
        by_proj.setdefault(r['project'], []).append(r)
    for proj, items in sorted(by_proj.items()):
        print(f"\n  {c(B, proj)} ({len(items)})")
        for r in items:
            log_tag = c(GR,'[log=1]') if r['on_crash_log'] else c(DIM,'[log=0]')
            print(f"    {r['localId']:>11}  {r['crash_type'][:40]:<40}  {log_tag}")

    log1 = sum(1 for r in selected if r['on_crash_log'])
    print(f"\n  on_crash_log=1: {c(GR,log1)}   on_crash_log=0: {c(DIM,len(selected)-log1)}")
    print(f"  Channel : {c(YL, ntfy_channel_str())}")
    print(f"  Workers : {c(YL, n_workers)}  (rootainer-0 … rootainer-{n_workers-1})")

    # Patch phase toggle
    cur_cfg = json.loads(CONFIG.read_text())
    cur_patch = cur_cfg.get('patch_enabled', False)
    print(f"\n  {c(B,'Patch phase')} (fix bug after localization — one attempt):")
    print(f"    {c(CY,'[y]')} Enable   {c(CY,'[n]')} Disable   "
          f"{c(DIM, f'(currently: {\"ON\" if cur_patch else \"OFF\"}')})")
    patch_enabled = (prompt("Patch phase", "y" if cur_patch else "n").lower() == 'y')
    print(f"  Patch phase: {c(GR,'ENABLED') if patch_enabled else c(DIM,'DISABLED')}")

    if not confirm("\n  Save and update caro_monitor.sh?"):
        return

    # Save patch_enabled to base config (worker configs inherit from it)
    cur_cfg['patch_enabled'] = patch_enabled
    CONFIG.write_text(json.dumps(cur_cfg, indent=4))
    print(c(GR, f"  ✓ patch_enabled={str(patch_enabled).lower()} saved to experiment_setup.json"))

    ids = [r['localId'] for r in selected]
    save_monitor_ids(ids)
    print(c(GR, f"\n  ✓ {len(ids)} IDs written to caro_monitor.sh"))

    # Push claimed IDs to GitHub BEFORE launching — blocks other machines from picking them
    print(f"  {c(DIM,'Pushing claimed IDs to GitHub...')} ", end='', flush=True)
    push_ok, push_msg = push_claimed_ids(ids)
    if push_ok:
        print(c(GR, f'✓  ({len(ids)} IDs now blocked on remote)'))
    else:
        print(c(YL, f'⚠  Push failed — run `git push` manually to sync\n  {c(DIM, push_msg)}'))

    # Ensure worker configs exist
    for i in range(n_workers):
        wpath = DIR / f'experiment_setup_w{i}.json'
        if not wpath.exists():
            make_worker_config(i)
            print(c(GR, f"  ✓ Created experiment_setup_w{i}.json"))

    if confirm("  Launch caro_monitor.sh now?"):
        subprocess.Popen(['bash', str(MONITOR)], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, cwd=str(DIR))
        print(c(GR, "\n  ✓ Monitor launched."))
        print(f"    tail:    {c(CY, f'tail -f {DIR}/monitor.log')}")
        print(f"    channel: {c(YL, ntfy_channel_str())}\n")
    else:
        print(f"\n  Run: {c(CY,'bash caro_monitor.sh')}\n")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    os.system('clear')
    total, unique, cost, events = run_summary()
    already = len(get_already_run())
    n_workers = get_monitor_workers()
    channel = ntfy_channel_str()

    print(f"\n{B}{CY}  ╔════════════════════════════════════════════╗")
    print(f"  ║   CARO — Experiment Setup                  ║")
    print(f"  ╚════════════════════════════════════════════╝{R}")
    synced_count = len(get_synced_ids())
    print(f"\n  {c(DIM,'Runs:')} {c(GR,total)}  "
          f"{c(DIM,'Vulns:')} {c(GR,unique)}  "
          f"{c(DIM,'Cost:')} {c(YL,f'${cost:.2f}')}  "
          f"{c(DIM,'Workers:')} {c(YL,n_workers)}  "
          f"{c(DIM,'Synced claimed:')} {c(YL,synced_count)}")
    print(f"  {c(DIM,'Channel:')} {c(YL, channel)}")

    while True:
        already = len(get_already_run())
        n_workers = get_monitor_workers()
        print(f"\n  {c(B,'Menu')}")
        print(f"    {c(CY,'[1]')} Setup new batch")
        print(f"    {c(CY,'[2]')} View existing runs")
        print(f"    {c(CY,'[3]')} DB summary  ({already} already-run IDs)")
        print(f"    {c(CY,'[4]')} Worker setup  ({n_workers} workers active)")
        print(f"    {c(CY,'[5]')} Notification settings  [{c(YL, ntfy_channel_str())}]")
        print(f"    {c(CY,'[q]')} Quit")
        choice = prompt("").lower()

        if choice == '1':   setup_batch()
        elif choice == '2': view_runs()
        elif choice == '3': view_db_summary()
        elif choice == '4': setup_workers()
        elif choice == '5': setup_notifications()
        elif choice == 'q':
            print(f"\n  {c(DIM,'Bye.')}\n")
            sys.exit(0)

if __name__ == '__main__':
    main()
