# note this should be moved to a new file
# it handles the logic for syncing claimed IDs across multiple machines via git
# the IDs must be released if the run is not executed after claiming,
# to avoid them being locked indefinitely. --> (BUG)
# ===== Locked IDs logic for multi-machine sync ==============================
import json
import subprocess
from pathlib import Path

DIR           = Path(__file__).parent
SYNCED_FILE   = DIR / 'config' / 'synced_ids.json'
LOCAL_CLAIMED = DIR / 'config' / '.local_claimed.json'


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

    """
 ***********************
--BUG NOTE--: If two machines claim the same ID before syncing, they will both think they have
    it locked and may not release it properly, leading to potential duplicates or locked IDs. To mitigate this,
    always sync with GitHub before claiming new IDs, and release any unrun IDs promptly.
---------------------------------
    TODO: The lock system must be broken down by project and state the tester ID
    (e.g., "claimed": {"projectA": {"tester1": [1,2,3], "tester2": [4,5]}, "projectB": ...}})
---------------------------------
    Rational:-
    to avoid cross-project conflicts and allow better tracking of who claimed what.
---------------------------------
*************************
"""

def get_local_claimed():
    """IDs this machine has claimed (may include unrun ones)."""
    if not LOCAL_CLAIMED.exists():
        return set()
    try:
        return set(json.loads(LOCAL_CLAIMED.read_text()).get('ids', []))
    except Exception:
        return set()




def save_local_claimed(ids: set):
    LOCAL_CLAIMED.write_text(json.dumps({'ids': sorted(ids)}, indent=2) + '\n')



def release_claimed_ids(ids_to_release: list, max_retries: int = 3):
    """Remove ids from synced_ids.json and push. Returns (success, message)."""
    for _ in range(max_retries):
        subprocess.run(['git', 'pull', '--rebase', '--autostash'],
                       cwd=str(DIR), capture_output=True)
        updated = sorted(get_synced_ids() - set(ids_to_release))
        SYNCED_FILE.write_text(json.dumps({'claimed': updated}, indent=2) + '\n')
        subprocess.run(['git', 'add', str(SYNCED_FILE)], cwd=str(DIR), capture_output=True)
        subprocess.run(
            ['git', 'commit', '-m', f'chore: release {len(ids_to_release)} ARVO IDs'],
            cwd=str(DIR), capture_output=True
        )
        r = subprocess.run(['git', 'push'], cwd=str(DIR), capture_output=True, text=True)
        if r.returncode == 0:
            return True, r.stdout.strip()
    return False, f'Push failed after {max_retries} attempts'

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


# ===== the end of locked IDs logic ==============================
