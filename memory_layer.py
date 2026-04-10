"""Memory layer: synthesize and recall repair contracts as Datalog rules.

Phase 1 - viewer / standalone learning loop. caro.py is NOT modified.

Workflow:
  synthesize_contract(run_id)
      Read a completed patch run. Fetch the ground-truth diff from
      arvo.patch_url. Ask Claude to emit a pyDatalog rule capturing the
      transferable invariant the real fix enforced. Append to memory.dl.

  recall(arvo_id)
      Extract the bug's symbolic conditions (deterministic + LLM, then
      reconciled). Assert the union as ephemeral facts, query memory.dl,
      return the matching contract names. Retract the facts so the next
      call starts clean.

  CLI:
      python3 memory_layer.py show
      python3 memory_layer.py recall <arvo_id>
      python3 memory_layer.py synthesize <run_id>
      python3 memory_layer.py backfill
"""

import argparse
import base64
import json
import logging
import re
import sqlite3
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Optional

from pyDatalog import pyDatalog

from memory_vocab import (
    BUG_TYPES,
    PREDICATE_ARITY,
    PREDICATE_NAMES,
    PREDICATES,
    vocab_block,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(name)s] - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger('memory_layer')

DB_PATH = 'arvo_loc_runs.db'
MEMORY_PATH = Path(__file__).parent / 'memory.dl'


# ---- pyDatalog setup ------------------------------------------------------

_TERMS_INITIALIZED = False


def _init_terms():
    """Declare every predicate name + a pool of rule-body variables.

    Must be called before loading memory.dl or asserting any facts, because
    pyDatalog needs the predicate symbols to exist as Python globals.
    """
    global _TERMS_INITIALIZED
    if _TERMS_INITIALIZED:
        return
    pyDatalog.create_terms(','.join(PREDICATE_NAMES + ['contract_fires']))
    # Generic uppercase variables for use in rule bodies. memory.dl rules
    # are hand-written or LLM-written using these names.
    pyDatalog.create_terms('X, Y, Z, F, G, L, M, T, S, X1, X2, F1, F2, L1, L2')
    # pyDatalog refuses to evaluate a queried rule whose body references a
    # predicate that has never had a fact asserted, even if the answer is
    # "no rows". Seed each predicate with a sentinel assert+retract so the
    # engine knows it exists but starts empty.
    sentinel = '__sentinel__'
    for name, arity in PREDICATE_ARITY.items():
        args = ', '.join([f"'{sentinel}'"] * arity)
        try:
            pyDatalog.load(f'+ {name}({args})')
            pyDatalog.load(f'- {name}({args})')
        except Exception as e:
            logger.warning(f'failed to seed {name}/{arity}: {e}')
    _TERMS_INITIALIZED = True


def load_memory():
    """Load every contract rule from memory.dl into the engine."""
    _init_terms()
    if not MEMORY_PATH.exists():
        logger.warning(f'{MEMORY_PATH} does not exist; memory is empty')
        return
    text = MEMORY_PATH.read_text()
    if not text.strip():
        return
    try:
        pyDatalog.load(text)
    except Exception as e:
        logger.error(f'failed to load {MEMORY_PATH}: {e}')
        raise


# ---- DB helpers -----------------------------------------------------------

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_arvo_context(arvo_id: int) -> Optional[dict]:
    with _conn() as c:
        row = c.execute(
            'SELECT localId, project, crash_type, sanitizer, patch_url, '
            'crash_output FROM arvo WHERE localId = ?',
            (arvo_id,),
        ).fetchone()
        return dict(row) if row else None


def get_completed_patch_runs() -> list:
    with _conn() as c:
        return [
            dict(r)
            for r in c.execute(
                'SELECT p.run_id, r.vuln_id, p.is_crash_resolved, p.agent_diff '
                'FROM patch_data p JOIN runs r ON r.run_id = p.run_id'
            ).fetchall()
        ]


def get_run_vuln_id(run_id: str) -> Optional[int]:
    with _conn() as c:
        row = c.execute(
            'SELECT vuln_id FROM runs WHERE run_id = ?', (run_id,)
        ).fetchone()
        return row['vuln_id'] if row else None


def get_run_agent_diff(run_id: str) -> Optional[str]:
    with _conn() as c:
        row = c.execute(
            'SELECT agent_diff FROM patch_data WHERE run_id = ?', (run_id,)
        ).fetchone()
        return row['agent_diff'] if row else None


# ---- Truth diff fetching --------------------------------------------------

def fetch_truth_diff(patch_url: str) -> Optional[str]:
    """Best-effort: convert a public commit URL to a unified diff."""
    if not patch_url:
        return None
    try:
        if 'github.com' in patch_url and '/commit/' in patch_url:
            url = patch_url.rstrip('/') + '.diff'
            return _http_get(url)
        # GitLab (gitlab.com and self-hosted like gitlab.gnome.org) uses the
        # same /-/commit/<sha> route and accepts a .diff suffix.
        if 'gitlab' in patch_url and '/-/commit/' in patch_url:
            url = patch_url.rstrip('/') + '.diff'
            return _http_get(url)
        if 'googlesource.com' in patch_url:
            sep = '&' if '?' in patch_url else '?'
            url = patch_url + f'{sep}format=text'
            raw = _http_get(url)
            try:
                return base64.b64decode(raw).decode('utf-8', errors='replace')
            except Exception:
                return raw
    except Exception as e:
        logger.warning(f'fetch_truth_diff failed for {patch_url}: {e}')
        return None
    logger.info(f'unsupported patch host (skipping): {patch_url}')
    return None


def _http_get(url: str, timeout: int = 20) -> str:
    req = urllib.request.Request(
        url, headers={'User-Agent': 'arvo-memory-layer/0.1'}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8', errors='replace')


# ---- Claude shell-out -----------------------------------------------------

def call_claude(prompt: str) -> str:
    """Shell out to the local `claude` CLI and return the assistant text."""
    cmd = ['claude', '-p', prompt, '--output-format', 'json']
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True, timeout=300
        )
    except FileNotFoundError:
        logger.error('claude CLI not found on PATH')
        return ''
    except subprocess.CalledProcessError as e:
        logger.error(f'claude CLI failed: {e.stderr[:500]}')
        return ''
    except subprocess.TimeoutExpired:
        logger.error('claude CLI timed out after 300s')
        return ''
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.error(f'claude CLI returned non-JSON: {result.stdout[:200]}')
        return ''
    return data.get('result', '') or ''


# ---- Condition extraction -------------------------------------------------

# A "fact" is a string like "passed_by_ref(var1, func1)" - exactly the
# shape pyDatalog accepts inside `+ ...` and `- ...` directives.
FACT_RE = re.compile(r'^([a-z_][a-z0-9_]*)\s*\(([^)]*)\)\s*$')


def parse_facts(text: str) -> set:
    """Pull predicate(arg, ...) lines out of arbitrary LLM text.

    Tolerant of: trailing periods/commas, leading bullets, surrounding code
    fences, prose lines mixed in. Anything that doesn't match the regex or
    references a predicate not in the vocabulary is dropped.
    """
    out = set()
    for raw in text.splitlines():
        line = raw.strip()
        # Strip common LLM noise
        for prefix in ('-', '*', '+', '·', '•'):
            if line.startswith(prefix):
                line = line[len(prefix):].strip()
                break
        line = line.rstrip('.').rstrip(',').strip()
        if not line or line.startswith('%') or line.startswith('#'):
            continue
        m = FACT_RE.match(line)
        if not m:
            continue
        pred = m.group(1)
        if pred not in PREDICATE_NAMES:
            continue
        # Normalise: collapse whitespace inside the args
        args = ', '.join(a.strip() for a in m.group(2).split(','))
        out.add(f"{pred}({args})")
    return out


def _bug_type_from_crash_type(crash_type: str) -> Optional[str]:
    if not crash_type:
        return None
    c = crash_type.lower()
    mapping = [
        ('heap-buffer-overflow', 'heap_buffer_overflow'),
        ('stack-buffer-overflow', 'stack_buffer_overflow'),
        ('global-buffer-overflow', 'global_buffer_overflow'),
        ('container-overflow', 'container_overflow'),
        ('null-deref', 'null_pointer_dereference'),
        ('null deref', 'null_pointer_dereference'),
        ('null pointer', 'null_pointer_dereference'),
        ('heap-use-after-free', 'use_after_free'),
        ('use-after-free', 'use_after_free'),
        ('use-after-return', 'use_after_return'),
        ('double-free', 'double_free'),
        ('uninitialized', 'uninitialized_read'),
        ('integer-overflow', 'integer_overflow'),
        ('signed-integer-overflow', 'signed_integer_overflow'),
        ('type confusion', 'type_confusion'),
        ('memory leak', 'memory_leak'),
    ]
    for needle, bug in mapping:
        if needle in c:
            return bug
    return None


def extract_conditions_det(arvo: dict) -> set:
    """Cheap deterministic extraction over crash_type + crash_output.

    Intentionally minimal. This is the honesty check on the LLM extractor:
    when the two sides disagree, we get an audit trail. Expand the patterns
    over time as the vocabulary proves itself.
    """
    facts = set()
    bug = _bug_type_from_crash_type(arvo.get('crash_type') or '')
    if bug:
        facts.add(f'bug_class({bug})')

    if bug == 'null_pointer_dereference':
        facts.add('dereferenced_at(var1, loc1)')
    elif bug == 'use_after_free':
        facts.add('frees(func1, var1)')
        facts.add('used_after(var1, loc1)')
    elif bug == 'double_free':
        facts.add('frees(func1, var1)')
        facts.add('frees(func2, var1)')
    elif bug in ('heap_buffer_overflow', 'stack_buffer_overflow',
                 'global_buffer_overflow', 'container_overflow',
                 'index_out_of_bounds'):
        facts.add('indexed_at(var1, loc1, size1)')
    elif bug == 'uninitialized_read':
        facts.add('allocates(func1, var1)')
        facts.add('used_after(var1, loc1)')

    return facts


def extract_conditions_llm(
    arvo: dict,
    agent_diff: Optional[str] = None,
    truth_diff: Optional[str] = None,
) -> set:
    """Ask Claude to emit symbolic facts for this bug, in our vocabulary."""
    diff_block = ''
    if truth_diff:
        diff_block += f'\nGROUND-TRUTH DIFF (truncated):\n{truth_diff[:4000]}\n'
    if agent_diff:
        diff_block += f'\nAGENT PATCH DIFF (truncated):\n{agent_diff[:4000]}\n'

    prompt = f"""You are extracting symbolic bug conditions for a Datalog memory layer.

Project:     {arvo.get('project')}
Crash type:  {arvo.get('crash_type')}
Sanitizer:   {arvo.get('sanitizer')}

CRASH OUTPUT (truncated):
{(arvo.get('crash_output') or '')[:3000]}
{diff_block}
{vocab_block()}

OUTPUT FORMAT (strict):
- Emit ONLY lines of the form `predicate(arg, arg, ...)`. No leading bullet,
  no trailing period.
- Use ONLY predicate names listed above.
- Use ONLY the abstract symbols listed above (var1, func1, loc1, ...) as
  arguments. NEVER use real names from the project, file, or function.
- Reuse the same symbol when the same entity recurs across facts (var1
  appearing twice means the same value).
- One fact per line. No prose, no markdown fences, no commentary.

Begin output now:"""
    text = call_claude(prompt)
    return parse_facts(text)


def reconcile(det: set, llm: set) -> dict:
    return {
        'agreed': det & llm,
        'det_only': det - llm,
        'llm_only': llm - det,
    }


# ---- Recall ---------------------------------------------------------------

def _assert_facts(facts):
    for f in facts:
        try:
            pyDatalog.load('+ ' + f)
        except Exception as e:
            logger.warning(f'failed to assert {f}: {e}')


def _retract_facts(facts):
    for f in facts:
        try:
            pyDatalog.load('- ' + f)
        except Exception as e:
            logger.warning(f'failed to retract {f}: {e}')


def _query_contracts() -> list:
    ans = pyDatalog.ask('contract_fires(X)')
    if not ans or not ans.answers:
        return []
    return sorted({row[0] for row in ans.answers})


def recall(arvo_id: int, use_llm: bool = True) -> dict:
    """Return contracts that fire for this bug's symbolic conditions."""
    load_memory()
    arvo = get_arvo_context(arvo_id)
    if not arvo:
        return {'error': f'arvo id {arvo_id} not found'}

    det = extract_conditions_det(arvo)
    llm = extract_conditions_llm(arvo) if use_llm else set()
    rec = reconcile(det, llm)
    union = det | llm

    _assert_facts(union)
    try:
        contracts = _query_contracts()
    finally:
        _retract_facts(union)

    return {
        'arvo_id': arvo_id,
        'project': arvo.get('project'),
        'crash_type': arvo.get('crash_type'),
        'extracted_det': sorted(det),
        'extracted_llm': sorted(llm),
        'agreed': sorted(rec['agreed']),
        'det_only': sorted(rec['det_only']),
        'llm_only': sorted(rec['llm_only']),
        'contracts': contracts,
    }


# ---- Synthesis ------------------------------------------------------------

def synthesize_contract(run_id: str) -> Optional[str]:
    """Generate a new contract from a completed patch run; append to memory.dl.

    Returns the contract block that was appended, or None on failure.
    """
    vuln_id = get_run_vuln_id(run_id)
    if vuln_id is None:
        logger.error(f'run {run_id} not found')
        return None
    arvo = get_arvo_context(vuln_id)
    if not arvo:
        logger.error(f'arvo {vuln_id} not found')
        return None

    truth_diff = fetch_truth_diff(arvo.get('patch_url') or '')
    agent_diff = get_run_agent_diff(run_id)

    if not truth_diff and not agent_diff:
        logger.warning(
            f'{run_id}: no truth diff and no agent diff - nothing to learn from'
        )
        return None

    diff_block = ''
    if truth_diff:
        diff_block += f'\nGROUND-TRUTH DIFF (the real upstream fix, truncated):\n{truth_diff[:6000]}\n'
    if agent_diff:
        diff_block += f'\nAGENT PATCH DIFF (what the patching agent produced, truncated):\n{agent_diff[:6000]}\n'

    bug = _bug_type_from_crash_type(arvo.get('crash_type') or '') or 'unknown'

    prompt = f"""You are learning a transferable repair contract for a Datalog memory layer.

Project:    {arvo.get('project')}
Crash type: {arvo.get('crash_type')}
Bug class:  {bug}

CRASH OUTPUT (truncated):
{(arvo.get('crash_output') or '')[:2500]}
{diff_block}
{vocab_block()}

YOUR TASK:
Read the ground-truth diff (and agent diff if present). Identify the
*invariant* the real fix enforces - the precondition or post-call check
that, if applied, would prevent this class of bug. Express that invariant
as a single pyDatalog contract rule.

OUTPUT FORMAT (strict):
- First emit a comment block exactly in this shape (use # for comments,
  NOT %% which is invalid Python syntax):

# CONTRACT
# Source:    {run_id}  (arvo {vuln_id}, project {arvo.get('project')})
# Class:     {bug}
# Intuition: <one sentence in plain English describing the invariant>

- Then emit ONE pyDatalog rule of exactly this shape:

contract_fires('<snake_case_contract_name>') <= (
    <predicate(VAR, ...)> &
    <predicate(VAR, ...)> &
    ...
)

RULES:
- Use ONLY the predicate names from the vocabulary above.
- Use UPPERCASE single-letter or letter+digit names for rule-body variables
  (X, Y, F, L, X1, F1, L1 ...). NEVER use concrete project names, file
  names, function names, or numeric literals.
- The body must be 2-5 conjuncts. Keep it minimal but specific.
- The contract name should describe the invariant ('must_<verb>_<object>').
- Output only the comment block and the rule. No prose, no fences.

Begin output now:"""
    text = call_claude(prompt)
    if not text.strip():
        logger.error(f'{run_id}: empty response from claude')
        return None

    # Light validation: must contain `contract_fires(` and `<=`
    if 'contract_fires(' not in text or '<=' not in text:
        logger.error(f'{run_id}: response missing contract_fires/<= pattern:\n{text[:400]}')
        return None

    # Sanitise LLM output: replace %% / % comments with #, strip fences.
    lines = []
    for line in text.strip().splitlines():
        stripped = line.lstrip()
        if stripped.startswith('%%'):
            line = line.replace('%%', '#', 1)
        elif stripped.startswith('%') and not stripped.startswith('%s'):
            line = line.replace('%', '#', 1)
        if stripped.startswith('```'):
            continue
        lines.append(line)
    block = '\n' + '\n'.join(lines) + '\n'
    with MEMORY_PATH.open('a', encoding='utf-8') as f:
        f.write(block)
    logger.info(f'{run_id}: appended contract to {MEMORY_PATH}')
    return block


def backfill():
    runs = get_completed_patch_runs()
    if not runs:
        logger.warning('no completed patch runs to backfill from')
        return
    logger.info(f'backfilling {len(runs)} patch runs')
    for r in runs:
        logger.info(f"--- {r['run_id']} (vuln {r['vuln_id']}) ---")
        synthesize_contract(r['run_id'])


# ---- CLI ------------------------------------------------------------------

def cmd_show(_args):
    if not MEMORY_PATH.exists():
        print(f'(no memory file at {MEMORY_PATH})')
        return
    print(MEMORY_PATH.read_text())


def cmd_recall(args):
    out = recall(args.arvo_id, use_llm=not args.no_llm)
    print(json.dumps(out, indent=2))


def cmd_synthesize(args):
    block = synthesize_contract(args.run_id)
    if block:
        print(block)


def cmd_backfill(_args):
    backfill()


def main():
    p = argparse.ArgumentParser(description='ARVO patching memory layer')
    sub = p.add_subparsers(dest='cmd', required=True)

    sub.add_parser('show', help='print memory.dl').set_defaults(func=cmd_show)

    pr = sub.add_parser('recall', help='show contracts that fire for an arvo bug')
    pr.add_argument('arvo_id', type=int)
    pr.add_argument('--no-llm', action='store_true',
                    help='deterministic extraction only (skip claude call)')
    pr.set_defaults(func=cmd_recall)

    ps = sub.add_parser('synthesize', help='learn a contract from one run')
    ps.add_argument('run_id', type=str)
    ps.set_defaults(func=cmd_synthesize)

    sub.add_parser('backfill',
                   help='synthesize contracts from every completed patch run'
                   ).set_defaults(func=cmd_backfill)

    args = p.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
