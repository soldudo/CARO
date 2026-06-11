"""patch_eval.py

Score patch runs against the ground-truth fix (``ground_truth`` table, built
by ground_truth.py) and characterize each patch, writing one row per patch
run to a ``patch_eval`` table.

Three groups of measurements per run:

**Agreement with the maintainer's fix** (Tier 1, mechanical):
  file Jaccard / any-file overlap (suffix-matched paths), minimum line
  distance between agent hunks and the fix's changed lines on the old
  (vulnerable) side of shared files, and a size ratio (agent changed lines /
  ground-truth code changed lines). Summarized as ``agreement``:
  ``line`` (hunks overlap within --line-tol) > ``file`` > ``divergent``;
  ``no_patch`` when the run produced nothing, ``no_gt`` when the ground
  truth has no code files to compare against (suspect fixes).

**Crash-site placement** (the superficial-fix signal): the sanitizer stack in
  ``arvo.crash_output`` gives the crashing frames (function/file/line). A
  patch whose hunks sit within --frame-tol lines of a top crash frame, when
  the real fix is elsewhere, is the classic symptomatic patch. Both the
  agent's and the ground truth's distances to the crash frames are recorded.

**Edit taxonomy** (Tier 2, heuristic): each agent hunk is classified by its
  added lines (bounds_check / init / alloc_fix / len_clamp / type_change /
  delete_only / other) into ``category_counts`` + ``dominant_category``.

Context columns (experiment_id, has_loc_context, is_crash_resolved, and the
localization run's accuracy via ``loc_eval_runs``) are joined in so the
experiment-1-vs-2 and loc->patch comparisons are single GROUP BYs away.

Run after ground_truth.py (and ideally loc_eval.py)::

    python patch_eval.py [--db ../arvo_loc_runs.db] [--line-tol N] [--frame-tol N]
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3

from loc_eval import match_file, range_distance

DB_PATH = "../arvo_loc_runs.db"
DEFAULT_LINE_TOL = 10
DEFAULT_FRAME_TOL = 10


# --- agent diff parsing -------------------------------------------------------
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_FILE_HDR_RE = re.compile(r"^--- (?:a/)?(.+?)\s*$")


def parse_agent_diff(diff_text: str, default_file: str) -> list[dict]:
    """Parse a bare unified diff ('--- a/x' / '+++ b/x' / '@@') into hunks.

    Agent diffs carry no 'diff --git' header; the patch entry's ``file``
    field is authoritative when the ---/+++ header is missing or unhelpful.
    Returns hunk dicts with old-side changed line numbers (add-only hunks
    anchor to the old-side start so every hunk maps to a location).
    """
    hunks: list[dict] = []
    cur_file = default_file
    cur: dict | None = None
    old_ln = 0

    def close():
        nonlocal cur
        if cur is not None:
            if not cur["old_changed_lines"]:
                cur["old_changed_lines"] = [cur["old_start"]]
            hunks.append(cur)
            cur = None

    for line in (diff_text or "").splitlines():
        m = _FILE_HDR_RE.match(line)
        if m and not line.startswith("--- a/dev/null"):
            close()
            path = m.group(1)
            if path not in ("/dev/null", ""):
                cur_file = path
            continue
        m = _HUNK_RE.match(line)
        if m:
            close()
            cur = {
                "file": cur_file or default_file,
                "old_start": int(m.group(1)),
                "old_len": int(m.group(2) or 1),
                "added": 0,
                "removed": 0,
                "old_changed_lines": [],
                "added_lines_text": [],
            }
            old_ln = cur["old_start"]
            continue
        if cur is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            cur["added"] += 1
            cur["added_lines_text"].append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            cur["removed"] += 1
            cur["old_changed_lines"].append(old_ln)
            old_ln += 1
        elif not line.startswith("\\"):
            old_ln += 1
    close()
    return hunks


# --- edit taxonomy ------------------------------------------------------------
# Checked in order; first match wins.
_TAXONOMY = [
    ("alloc_fix", re.compile(
        r"\b(malloc|calloc|realloc|reallocarray|av_malloc\w*|xmlRealloc|"
        r"xmlMalloc|new\s*\[)", re.IGNORECASE)),
    ("init", re.compile(
        r"\bmemset\s*\(|=\s*(0|NULL|nullptr|\{\s*0?\s*\})\s*[;,]|"
        r"=\s*\{\s*\}")),
    ("len_clamp", re.compile(
        r"\b(MIN|FFMIN|min)\s*\(|\bclamp|%\s*\w*(size|len)", re.IGNORECASE)),
    ("bounds_check", re.compile(
        r"\bif\s*\(.*?(<=|>=|<|>|==|!=).*?\)|\breturn\b.*?(NULL|-1|0|false|"
        r"error|FAILURE)|\bgoto\s+\w*(err|fail|out|done)", re.IGNORECASE)),
    ("type_change", re.compile(
        r"\b(size_t|uint64_t|int64_t|uint32_t|ptrdiff_t|unsigned\s+long)\b")),
]


def classify_hunk(hunk: dict) -> str:
    added = "\n".join(hunk.get("added_lines_text") or [])
    if not added.strip():
        return "delete_only"
    for name, rx in _TAXONOMY:
        if rx.search(added):
            return name
    return "other"


# --- crash stack parsing --------------------------------------------------------
_FRAME_RE = re.compile(
    r"^\s*#(\d+)\s+0x[0-9a-f]+\s+in\s+(\S+)\s+(/\S+?):(\d+)", re.MULTILINE)
_NOISE_PATH = re.compile(
    r"/(libfuzzer|llvm|compiler-rt|glibc|aflplusplus)/|/usr/|/lib/",
    re.IGNORECASE)
_NOISE_FUNC = re.compile(r"^(__interceptor|__asan|__sanitizer|fuzzer::)")


def parse_crash_frames(crash_output: str, max_frames: int = 8) -> list[dict]:
    """Project frames of the *first* stack in a sanitizer report.

    Returns [{depth, function, file, line}] with depth = position among kept
    project frames (0 = innermost), skipping sanitizer/fuzzer scaffolding.
    """
    frames = []
    seen_first_stack = False
    for m in _FRAME_RE.finditer(crash_output or ""):
        idx = int(m.group(1))
        if idx == 0:
            if seen_first_stack:
                break          # a second '#0' starts the next stack
            seen_first_stack = True
        func, path, line = m.group(2), m.group(3), int(m.group(4))
        if _NOISE_PATH.search(path) or _NOISE_FUNC.match(func):
            continue
        frames.append({"depth": len(frames), "function": func,
                       "file": path, "line": line})
        if len(frames) >= max_frames:
            break
    return frames


def min_frame_distance(hunks: list[dict], frames: list[dict]
                       ) -> tuple[int | None, int | None]:
    """(min line distance to a crash frame in the same file, frame depth)."""
    best, best_depth = None, None
    for h in hunks:
        ranges = [(ln, ln) for ln in h["old_changed_lines"]]
        for fr in frames:
            kind, _ = match_file(h["file"], [fr["file"]])
            if kind == "none":
                continue
            d = range_distance(ranges, [fr["line"]])
            if d is not None and (best is None or d < best):
                best, best_depth = d, fr["depth"]
    return best, best_depth


# --- scoring -------------------------------------------------------------------
def score_patch(patches: list[dict], gt: dict | None, frames: list[dict],
                line_tol: int, frame_tol: int) -> dict:
    """All comparison features for one run's patches list."""
    hunks: list[dict] = []
    agent_files: list[str] = []
    for p in patches:
        f = p.get("file") or ""
        if f and f not in agent_files:
            agent_files.append(f)
        hunks.extend(parse_agent_diff(p.get("diff") or "", f))

    cats = {}
    for h in hunks:
        c = classify_hunk(h)
        cats[c] = cats.get(c, 0) + 1
    dominant = max(cats, key=lambda c: (cats[c], c)) if cats else None

    rec = {
        "n_patch_files": len(agent_files),
        "n_patch_hunks": len(hunks),
        "added_lines": sum(h["added"] for h in hunks),
        "removed_lines": sum(h["removed"] for h in hunks),
        "category_counts": json.dumps(cats),
        "dominant_category": dominant,
        "patch_hunks_json": json.dumps(hunks),
        "file_jaccard": None, "n_common_files": None, "file_hit": None,
        "min_gt_line_distance": None, "gt_line_hit": None, "size_ratio": None,
        "agreement": "no_patch" if not hunks else None,
        "agent_min_frame_dist": None, "agent_frame_depth": None,
        "patched_at_crash_frame": None,
        "gt_min_frame_dist": None, "gt_at_crash_frame": None,
    }

    if hunks and frames:
        d, depth = min_frame_distance(hunks, frames)
        rec["agent_min_frame_dist"] = d
        rec["agent_frame_depth"] = depth
        rec["patched_at_crash_frame"] = int(d <= frame_tol) if d is not None else 0

    if not hunks:
        return rec
    gt_code_files = [f["path"] for f in gt["files"] if f["kind"] == "code"] \
        if gt else []
    if not gt_code_files:
        rec["agreement"] = "no_gt"
        return rec
    gt_hunks = [h for h in gt["hunks"] if h["file"] in gt_code_files]

    matched = {}      # agent file -> gt file
    for af in agent_files:
        kind, gf = match_file(af, gt_code_files)
        if kind != "none":
            matched[af] = gf
    union = len(set(gt_code_files) | {matched.get(af, af) for af in agent_files})
    rec["n_common_files"] = len(matched)
    rec["file_jaccard"] = round(len(set(matched.values())) / union, 3) if union else 0.0
    rec["file_hit"] = int(bool(matched))

    best = None
    for h in hunks:
        gf = matched.get(h["file"])
        if not gf:
            continue
        gt_lines = [ln for g in gt_hunks if g["file"] == gf
                    for ln in g.get("old_changed_lines", [])]
        d = range_distance([(ln, ln) for ln in h["old_changed_lines"]], gt_lines)
        if d is not None and (best is None or d < best):
            best = d
    rec["min_gt_line_distance"] = best
    rec["gt_line_hit"] = int(best is not None and best <= line_tol)

    gt_changed = sum(g["added"] + g["removed"] for g in gt_hunks)
    if gt_changed:
        rec["size_ratio"] = round(
            (rec["added_lines"] + rec["removed_lines"]) / gt_changed, 2)

    if frames:
        d, _ = min_frame_distance(
            [{"file": g["file"], "old_changed_lines": g["old_changed_lines"]}
             for g in gt_hunks], frames)
        rec["gt_min_frame_dist"] = d
        rec["gt_at_crash_frame"] = int(d <= frame_tol) if d is not None else 0

    rec["agreement"] = ("line" if rec["gt_line_hit"]
                        else "file" if rec["file_hit"] else "divergent")
    return rec


# --- db ------------------------------------------------------------------------
DDL = """
CREATE TABLE patch_eval (
    run_id                 TEXT PRIMARY KEY,
    vuln_id                INTEGER,
    project                TEXT,
    experiment_id          INTEGER,
    has_loc_context        INTEGER,
    loc_source             TEXT,
    loc_best_level         TEXT,    -- from loc_eval_runs (context runs only)
    is_crash_resolved      INTEGER,
    result_status          TEXT,
    n_patch_files          INTEGER,
    n_patch_hunks          INTEGER,
    added_lines            INTEGER,
    removed_lines          INTEGER,
    file_jaccard           REAL,
    n_common_files         INTEGER,
    file_hit               INTEGER,
    min_gt_line_distance   INTEGER, -- agent hunks vs GT changed lines (old side)
    gt_line_hit            INTEGER,
    size_ratio             REAL,    -- agent changed lines / GT code changed lines
    agreement              TEXT,    -- line | file | divergent | no_patch | no_gt
    dominant_category      TEXT,
    category_counts        TEXT,    -- json {category: n_hunks}
    agent_min_frame_dist   INTEGER, -- agent hunks vs sanitizer crash frames
    agent_frame_depth      INTEGER, -- depth of nearest frame (0 = innermost)
    patched_at_crash_frame INTEGER,
    gt_min_frame_dist      INTEGER,
    gt_at_crash_frame      INTEGER,
    gt_suspect             INTEGER,
    line_tol               INTEGER,
    frame_tol              INTEGER,
    patch_hunks_json       TEXT
)
"""


def evaluate(conn: sqlite3.Connection, line_tol: int, frame_tol: int) -> list[dict]:
    gts = {}
    for r in conn.execute("SELECT vuln_id, suspect_fix, files_json, hunks_json "
                          "FROM ground_truth WHERE error IS NULL"):
        gts[r["vuln_id"]] = {
            "suspect_fix": r["suspect_fix"],
            "files": json.loads(r["files_json"] or "[]"),
            "hunks": json.loads(r["hunks_json"] or "[]"),
        }
    frames_by_vuln = {
        r["localId"]: parse_crash_frames(r["crash_output"] or "")
        for r in conn.execute(
            "SELECT localId, crash_output FROM arvo WHERE localId IN "
            "(SELECT DISTINCT vuln_id FROM runs WHERE run_mode='patch')")}
    has_loc_eval = bool(conn.execute(
        "SELECT name FROM sqlite_master WHERE name='loc_eval_runs'").fetchone())

    rows = []
    runs = conn.execute("""
        SELECT r.run_id, r.vuln_id, r.result_json, r.experiment_id,
               a.project, p.loc_source, p.is_crash_resolved
        FROM runs r
        LEFT JOIN arvo a ON a.localId = r.vuln_id
        LEFT JOIN patch_data p ON p.run_id = r.run_id
        WHERE r.run_mode = 'patch' ORDER BY r.run_id
    """).fetchall()
    for run in runs:
        try:
            d = json.loads(run["result_json"]) if run["result_json"] else {}
        except json.JSONDecodeError:
            d = {}
        if not isinstance(d, dict):
            d = {}
        gt = gts.get(run["vuln_id"])
        loc_source = (run["loc_source"] or "").strip() or None
        loc_best = None
        if loc_source and has_loc_eval:
            hit = conn.execute("SELECT best_level FROM loc_eval_runs "
                               "WHERE run_id = ?", (loc_source,)).fetchone()
            loc_best = hit["best_level"] if hit else None

        rec = score_patch(d.get("patches") or [], gt,
                          frames_by_vuln.get(run["vuln_id"], []),
                          line_tol, frame_tol)
        rec.update({
            "run_id": run["run_id"],
            "vuln_id": run["vuln_id"],
            "project": run["project"],
            "experiment_id": run["experiment_id"],
            "has_loc_context": int(loc_source is not None),
            "loc_source": loc_source,
            "loc_best_level": loc_best,
            "is_crash_resolved": run["is_crash_resolved"],
            "result_status": d.get("status"),
            "gt_suspect": gt["suspect_fix"] if gt else None,
            "line_tol": line_tol,
            "frame_tol": frame_tol,
        })
        rows.append(rec)
    return rows


def store(conn: sqlite3.Connection, rows: list[dict]) -> None:
    conn.execute("DROP TABLE IF EXISTS patch_eval")
    conn.execute(DDL)
    for rec in rows:
        cols = ", ".join(rec)
        ph = ", ".join("?" * len(rec))
        conn.execute(f"INSERT INTO patch_eval ({cols}) VALUES ({ph})",
                     list(rec.values()))
    conn.commit()


# --- report --------------------------------------------------------------------
def _fmt(v, none="-"):
    return none if v is None else v


def _rate(vals: list) -> str:
    known = [v for v in vals if v is not None]
    if not known:
        return "n/a"
    return f"{sum(known)}/{len(known)} ({100 * sum(known) / len(known):.0f}%)"


def print_report(rows: list[dict]) -> None:
    print("=" * 100)
    print(f"patch_eval: {len(rows)} patch runs")
    print("=" * 100)
    for r in sorted(rows, key=lambda x: (x["project"] or "", x["run_id"])):
        flag = "  [GT SUSPECT]" if r["gt_suspect"] else ""
        ctx = "ctx" if r["has_loc_context"] else "   "
        print(f"  {r['run_id']:<40} {str(r['project']):<13} {ctx} "
              f"agree={str(r['agreement']):<9} "
              f"gtdist={_fmt(r['min_gt_line_distance']):<5} "
              f"sizex={_fmt(r['size_ratio']):<6} "
              f"crash-site={_fmt(r['patched_at_crash_frame'])} "
              f"cat={_fmt(r['dominant_category'])}{flag}")

    scored = [r for r in rows if r["agreement"] != "no_patch"
              and not r["gt_suspect"] and r["gt_suspect"] is not None]
    print(f"\nAgreement with maintainer fix ({len(scored)} runs with a patch "
          f"and non-suspect GT):")
    for level in ("line", "file", "divergent"):
        n = sum(1 for r in scored if r["agreement"] == level)
        print(f"  {level:<10} {n:>3}  ({100 * n / len(scored):.0f}%)")

    print("\nBy localization context (non-suspect GT):")
    for ctx, label in ((1, "WITH loc context"), (0, "baseline (env only)")):
        grp = [r for r in scored if r["has_loc_context"] == ctx]
        if not grp:
            continue
        sizes = sorted(r["size_ratio"] for r in grp if r["size_ratio"] is not None)
        med = sizes[len(sizes) // 2] if sizes else None
        print(f"  [{label}, n={len(grp)}] "
              f"line-agree: {_rate([int(r['agreement'] == 'line') for r in grp])}  "
              f"file-agree: {_rate([r['file_hit'] for r in grp])}  "
              f"at-crash-frame: {_rate([r['patched_at_crash_frame'] for r in grp])}  "
              f"median sizex: {_fmt(med)}")

    print("\nCrash-site placement vs ground truth (non-suspect GT):")
    both = [r for r in scored if r["patched_at_crash_frame"] is not None
            and r["gt_at_crash_frame"] is not None]
    sympt = [r for r in both
             if r["patched_at_crash_frame"] and not r["gt_at_crash_frame"]]
    print(f"  GT fix itself at a crash frame:    "
          f"{_rate([r['gt_at_crash_frame'] for r in both])}")
    print(f"  agent patched at a crash frame:    "
          f"{_rate([r['patched_at_crash_frame'] for r in both])}")
    print(f"  symptomatic suspects (agent at crash frame, GT elsewhere): "
          f"{len(sympt)}")
    for r in sympt:
        print(f"    {r['run_id']}  ({r['project']}, agree={r['agreement']})")

    ctx_runs = [r for r in scored if r["loc_best_level"]]
    if ctx_runs:
        print("\nloc->patch: patch agreement by localization accuracy "
              f"({len(ctx_runs)} context runs with scored loc source):")
        for lvl in ("line", "function", "file", "none"):
            grp = [r for r in ctx_runs if r["loc_best_level"] == lvl]
            if grp:
                print(f"  loc={lvl:<9} n={len(grp):<3} patch line-agree: "
                      f"{_rate([int(r['agreement'] == 'line') for r in grp])}")

    print("\nEdit taxonomy (dominant category, all runs with patches):")
    cats = {}
    for r in rows:
        if r["dominant_category"]:
            cats[r["dominant_category"]] = cats.get(r["dominant_category"], 0) + 1
    for c, n in sorted(cats.items(), key=lambda kv: -kv[1]):
        print(f"  {c:<14} {n}")
    print("=" * 100)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DB_PATH, help="path to runs SQLite db")
    ap.add_argument("--line-tol", type=int, default=DEFAULT_LINE_TOL,
                    help="max hunk distance (lines) counted as line agreement")
    ap.add_argument("--frame-tol", type=int, default=DEFAULT_FRAME_TOL,
                    help="max distance (lines) counted as at-crash-frame")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    try:
        if not conn.execute("SELECT name FROM sqlite_master "
                            "WHERE name='ground_truth'").fetchone():
            raise SystemExit("no ground_truth table - run ground_truth.py first")
        rows = evaluate(conn, args.line_tol, args.frame_tol)
        store(conn, rows)
        print_report(rows)
    finally:
        conn.close()


if __name__ == "__main__":
    main()


# --- tests (run via test runner or pytest) ---------------------------------------
_SAMPLE_DIFF = """\
--- a/parser.c
+++ b/parser.c
@@ -4446,7 +4446,7 @@ xmlParsePubidLiteral(xmlParserCtxt *ctxt) {
                 xmlFree(buf);
                 return(NULL);
             }
-\t    tmp = xmlRealloc(buf, size);
+\t    tmp = xmlRealloc(buf, newSize);
 \t    if (tmp == NULL) {
 \t\txmlErrMemory(ctxt);
 \t\txmlFree(buf);
"""

_SAMPLE_CRASH = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020
    #0 0x53c9e2 in peak_table /src/ffmpeg/libavcodec/cfhd.c:135:17
    #1 0x536887 in cfhd_decode /src/ffmpeg/libavcodec/cfhd.c:672:25
    #2 0x9a17ec in fuzzer::Fuzzer::ExecuteCallback(unsigned long) /src/libfuzzer/FuzzerLoop.cpp:526:13
    #3 0x52e5a4 in LLVMFuzzerTestOneInput /src/ffmpeg/tools/target_dec_fuzzer.c:215:23
allocated by thread T0 here:
    #0 0x4ec270 in __interceptor_posix_memalign /src/llvm/asan/asan_malloc_linux.cc:167
    #1 0x91aec6 in av_malloc /src/ffmpeg/libavutil/mem.c:87:9
"""


def test_parse_agent_diff():
    hunks = parse_agent_diff(_SAMPLE_DIFF, "parser.c")
    assert len(hunks) == 1
    h = hunks[0]
    assert h["file"] == "parser.c"
    assert h["old_start"] == 4446
    # the removed xmlRealloc line is the 4th line of the hunk -> 4449
    assert h["old_changed_lines"] == [4449]
    assert h["added"] == 1 and h["removed"] == 1


def test_parse_agent_diff_no_header():
    hunks = parse_agent_diff("@@ -10,2 +10,3 @@\n line\n+new\n line\n", "x.c")
    assert hunks[0]["file"] == "x.c"
    assert hunks[0]["old_changed_lines"] == [10]  # add-only anchors to start


def test_classify_hunk():
    mk = lambda lines: {"added_lines_text": lines}
    assert classify_hunk(mk(["    if (len > size) return NULL;"])) == "bounds_check"
    assert classify_hunk(mk(["    tmp = xmlRealloc(buf, newSize);"])) == "alloc_fix"
    assert classify_hunk(mk(["    float adv = 0;"])) == "init"
    assert classify_hunk(mk(["    n = FFMIN(n, size);"])) == "len_clamp"
    assert classify_hunk(mk([])) == "delete_only"
    assert classify_hunk(mk(["    do_thing();"])) == "other"


def test_parse_crash_frames():
    frames = parse_crash_frames(_SAMPLE_CRASH)
    # second stack (allocation) excluded; fuzzer scaffolding filtered out
    assert [f["function"] for f in frames] == [
        "peak_table", "cfhd_decode", "LLVMFuzzerTestOneInput"]
    assert frames[0]["line"] == 135 and frames[0]["depth"] == 0


def test_min_frame_distance():
    frames = parse_crash_frames(_SAMPLE_CRASH)
    hunks = [{"file": "libavcodec/cfhd.c", "old_changed_lines": [670, 696]}]
    d, depth = min_frame_distance(hunks, frames)
    assert d == 2 and depth == 1


def test_score_patch_agreement():
    gt = {
        "suspect_fix": 0,
        "files": [{"path": "parser.c", "kind": "code"}],
        "hunks": [{"file": "parser.c", "added": 1, "removed": 2,
                   "old_changed_lines": [4447, 4449]}],
    }
    rec = score_patch([{"file": "parser.c", "diff": _SAMPLE_DIFF}], gt, [],
                      line_tol=10, frame_tol=10)
    assert rec["file_hit"] == 1
    assert rec["min_gt_line_distance"] == 0
    assert rec["agreement"] == "line"
    assert rec["dominant_category"] == "alloc_fix"
    assert rec["size_ratio"] == round(2 / 3, 2)


def test_score_patch_no_patch():
    rec = score_patch([], None, [], 10, 10)
    assert rec["agreement"] == "no_patch" and rec["n_patch_hunks"] == 0


def test_score_patch_no_gt():
    gt = {"suspect_fix": 1,
          "files": [{"path": "tests/oss-fuzz.sh", "kind": "test_infra"}],
          "hunks": []}
    rec = score_patch([{"file": "x.c", "diff": _SAMPLE_DIFF}], gt, [], 10, 10)
    assert rec["agreement"] == "no_gt" and rec["file_hit"] is None
