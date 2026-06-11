"""loc_eval.py

Score localization runs against the ground-truth fix in the ``ground_truth``
table (built by ground_truth.py). For every vulnerability finding a loc run
reported (``runs.result_json`` -> ``vulnerabilities[]``), this measures
whether the agent pointed at the place the real fix changed, at three
granularities:

* **file**   - reported ``file`` matches a changed file (paths are compared
  by suffix, since agents report project-relative paths that occasionally
  differ in leading directories from the ground-truth diff's paths)
* **function** - reported ``method`` matches the enclosing function of a
  ground-truth hunk in that file (C++ qualifiers are stripped: the agent says
  ``NDPLayer::toString``, git hunk headers say ``toString``). NULL when the
  ground-truth diff exposes no function names for the matched file.
* **line**   - minimum distance between the reported line ranges and the
  fix's changed lines on the *old* (vulnerable) side; a hit within
  ``--line-tol`` (default 10) lines.

Interpretation caveat: the ground truth is where the *maintainer's fix*
landed, which is not always the only defensible root-cause location, so a
miss here means "did not point at the fix site", not necessarily "wrong".
Vulns whose recorded fix commit touches no shipped code (``suspect_fix=1``)
are scored but excluded from the aggregate rates.

Results land in two tables (rebuilt on every invocation):

* ``loc_eval``      - one row per reported finding
* ``loc_eval_runs`` - one row per loc run, for joining against patch runs
  via ``patch_data.loc_source``

Run::

    python loc_eval.py [--db ../arvo_loc_runs.db] [--line-tol N]
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3

DB_PATH = "../arvo_loc_runs.db"
DEFAULT_LINE_TOL = 10

# match-quality ordering for file paths
_MATCH_RANK = {"exact": 3, "suffix": 2, "basename": 1, "none": 0}


# --- normalization ----------------------------------------------------------
def norm_path(p: str) -> str:
    p = p.strip().replace("\\", "/").lstrip("/")
    for prefix in ("a/", "b/", "./"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    return p


def norm_function(name: str | None) -> str | None:
    """Strip C++ qualifiers and call parens: 'Foo::Bar(...)' -> 'Bar'."""
    if not name:
        return None
    name = name.strip()
    name = re.sub(r"\(.*$", "", name)          # drop parameter list
    name = name.split("::")[-1].strip()        # drop class/namespace
    return name or None


def match_file(reported: str, gt_paths: list[str]) -> tuple[str, str | None]:
    """Best (match_kind, gt_path) for a reported file against GT paths."""
    r = norm_path(reported)
    r_base = r.rsplit("/", 1)[-1]
    best = ("none", None)
    for g in gt_paths:
        gn = norm_path(g)
        if r == gn:
            kind = "exact"
        elif r.endswith("/" + gn) or gn.endswith("/" + r):
            kind = "suffix"
        elif r_base == gn.rsplit("/", 1)[-1]:
            kind = "basename"
        else:
            continue
        if _MATCH_RANK[kind] > _MATCH_RANK[best[0]]:
            best = (kind, g)
    return best


def parse_lines(lines) -> list[tuple[int, int]]:
    """['267-272', '1678', 90] -> [(267, 272), (1678, 1678), (90, 90)]."""
    out = []
    for item in lines or []:
        if isinstance(item, int):
            out.append((item, item))
            continue
        m = re.match(r"^\s*(\d+)\s*(?:-\s*(\d+))?\s*$", str(item))
        if m:
            a = int(m.group(1))
            b = int(m.group(2)) if m.group(2) else a
            out.append((min(a, b), max(a, b)))
    return out


def range_distance(ranges: list[tuple[int, int]], lines: list[int]) -> int | None:
    """Min distance between any reported range and any changed line (0=overlap)."""
    if not ranges or not lines:
        return None
    best = None
    for s, e in ranges:
        for ln in lines:
            d = 0 if s <= ln <= e else min(abs(ln - s), abs(ln - e))
            if best is None or d < best:
                best = d
    return best


# --- scoring ----------------------------------------------------------------
def score_finding(finding: dict, gt: dict, line_tol: int) -> dict:
    """Score one reported vulnerability against one ground-truth record.

    ``gt`` must carry ``files`` ([{path, kind}]), ``hunks`` (parsed
    hunks_json) and ``suspect_fix``.
    """
    reported_file = finding.get("file") or ""
    reported_method = finding.get("method")
    ranges = parse_lines(finding.get("lines"))

    gt_paths = [f["path"] for f in gt["files"]]
    file_match, gt_file = match_file(reported_file, gt_paths) if reported_file \
        else ("none", None)

    rec = {
        "confidence": finding.get("confidence_score"),
        "reported_file": reported_file,
        "reported_method": reported_method,
        "reported_lines": json.dumps(finding.get("lines") or []),
        "file_match": file_match,
        "file_hit": int(file_match != "none"),
        "matched_gt_file": gt_file,
        "matched_gt_function": None,
        "function_hit": None,
        "line_distance": None,
        "line_hit": None,
        "gt_suspect": gt["suspect_fix"],
    }
    if gt_file is None:
        rec["function_hit"] = 0 if reported_method else None
        rec["line_hit"] = 0 if ranges else None
        return rec

    file_hunks = [h for h in gt["hunks"] if h["file"] == gt_file]

    gt_funcs = {norm_function(h.get("function")) for h in file_hunks} - {None}
    if reported_method and gt_funcs:
        rep_fn = norm_function(reported_method)
        rec["function_hit"] = int(rep_fn in gt_funcs)
        if rec["function_hit"]:
            rec["matched_gt_function"] = rep_fn
    # gt_funcs empty -> function-level unknowable for this file: stays NULL

    changed = [ln for h in file_hunks for ln in h.get("old_changed_lines", [])]
    dist = range_distance(ranges, changed)
    if dist is not None:
        rec["line_distance"] = dist
        rec["line_hit"] = int(dist <= line_tol)
    return rec


def best_level(any_file: bool, any_func, any_line) -> str:
    if any_line:
        return "line"
    if any_func:
        return "function"
    if any_file:
        return "file"
    return "none"


# --- db ---------------------------------------------------------------------
DDL_FINDINGS = """
CREATE TABLE loc_eval (
    run_id              TEXT,
    vuln_id             INTEGER,
    finding_idx         INTEGER,
    confidence          REAL,
    reported_file       TEXT,
    reported_method     TEXT,
    reported_lines      TEXT,
    file_match          TEXT,    -- exact | suffix | basename | none
    file_hit            INTEGER,
    matched_gt_file     TEXT,
    function_hit        INTEGER, -- NULL when GT exposes no function names
    matched_gt_function TEXT,
    line_distance       INTEGER, -- min distance to a GT-changed old-side line
    line_hit            INTEGER, -- line_distance <= tolerance
    line_tol            INTEGER,
    gt_suspect          INTEGER,
    PRIMARY KEY (run_id, finding_idx)
)
"""

DDL_RUNS = """
CREATE TABLE loc_eval_runs (
    run_id            TEXT PRIMARY KEY,
    vuln_id           INTEGER,
    project           TEXT,
    n_findings        INTEGER,
    result_status     TEXT,
    any_file_hit      INTEGER,
    any_function_hit  INTEGER, -- NULL when no finding could be function-scored
    any_line_hit      INTEGER,
    best_level        TEXT,    -- line | function | file | none
    top_conf_file_hit INTEGER, -- file_hit of the highest-confidence finding
    mean_confidence   REAL,
    findings_hit_frac REAL,    -- fraction of findings with a file hit
    gt_suspect        INTEGER
)
"""


def load_ground_truth(conn: sqlite3.Connection) -> dict[int, dict]:
    gts = {}
    for r in conn.execute(
            "SELECT vuln_id, suspect_fix, files_json, hunks_json "
            "FROM ground_truth WHERE error IS NULL"):
        gts[r["vuln_id"]] = {
            "suspect_fix": r["suspect_fix"],
            "files": json.loads(r["files_json"] or "[]"),
            "hunks": json.loads(r["hunks_json"] or "[]"),
        }
    return gts


def evaluate(conn: sqlite3.Connection, line_tol: int
             ) -> tuple[list[dict], list[dict]]:
    gts = load_ground_truth(conn)
    finding_rows, run_rows = [], []
    runs = conn.execute("""
        SELECT r.run_id, r.vuln_id, r.result_json, a.project
        FROM runs r LEFT JOIN arvo a ON a.localId = r.vuln_id
        WHERE r.run_mode = 'loc' ORDER BY r.run_id
    """).fetchall()

    for run in runs:
        gt = gts.get(run["vuln_id"])
        try:
            d = json.loads(run["result_json"]) if run["result_json"] else {}
        except json.JSONDecodeError:
            d = {}
        if not isinstance(d, dict):
            d = {}
        findings = d.get("vulnerabilities") or []

        scored = []
        if gt:
            for i, f in enumerate(findings):
                rec = score_finding(f, gt, line_tol)
                rec.update({"run_id": run["run_id"], "vuln_id": run["vuln_id"],
                            "finding_idx": i, "line_tol": line_tol})
                scored.append(rec)
        finding_rows.extend(scored)

        func_known = [r["function_hit"] for r in scored
                      if r["function_hit"] is not None]
        confs = [r["confidence"] for r in scored if r["confidence"] is not None]
        top = max(scored, key=lambda r: r["confidence"] or 0) if scored else None
        any_file = any(r["file_hit"] for r in scored)
        any_func = max(func_known) if func_known else None
        any_line = any(r["line_hit"] for r in scored)
        run_rows.append({
            "run_id": run["run_id"],
            "vuln_id": run["vuln_id"],
            "project": run["project"],
            "n_findings": len(scored),
            "result_status": d.get("status"),
            "any_file_hit": int(any_file),
            "any_function_hit": any_func,
            "any_line_hit": int(any_line),
            "best_level": best_level(any_file, any_func, any_line),
            "top_conf_file_hit": top["file_hit"] if top else None,
            "mean_confidence": round(sum(confs) / len(confs), 1) if confs else None,
            "findings_hit_frac": round(
                sum(r["file_hit"] for r in scored) / len(scored), 3)
            if scored else None,
            "gt_suspect": gt["suspect_fix"] if gt else None,
        })
    return finding_rows, run_rows


def store(conn: sqlite3.Connection, finding_rows: list[dict],
          run_rows: list[dict]) -> None:
    conn.execute("DROP TABLE IF EXISTS loc_eval")
    conn.execute("DROP TABLE IF EXISTS loc_eval_runs")
    conn.execute(DDL_FINDINGS)
    conn.execute(DDL_RUNS)
    for table, rows in (("loc_eval", finding_rows),
                        ("loc_eval_runs", run_rows)):
        for rec in rows:
            cols = ", ".join(rec)
            ph = ", ".join("?" * len(rec))
            conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({ph})",
                         list(rec.values()))
    conn.commit()


# --- report -----------------------------------------------------------------
def _rate(hits: list) -> str:
    known = [h for h in hits if h is not None]
    if not known:
        return "n/a"
    return f"{sum(known)}/{len(known)} ({100 * sum(known) / len(known):.0f}%)"


def print_report(finding_rows: list[dict], run_rows: list[dict]) -> None:
    print("=" * 78)
    print(f"loc_eval: {len(run_rows)} loc runs, {len(finding_rows)} findings")
    print("=" * 78)
    for r in run_rows:
        flag = "  [GT SUSPECT]" if r["gt_suspect"] else ""
        fn = {None: "n/a", 0: "no", 1: "YES"}[r["any_function_hit"]]
        print(f"  {r['run_id']:<36} {str(r['project']):<13} "
              f"findings={r['n_findings']} best={r['best_level']:<8} "
              f"file={'YES' if r['any_file_hit'] else 'no':<3} "
              f"func={fn:<3} line={'YES' if r['any_line_hit'] else 'no'}{flag}")

    clean = [r for r in run_rows if not r["gt_suspect"] and r["n_findings"]]
    skipped = len(run_rows) - len(clean)
    print(f"\nAggregate over {len(clean)} runs "
          f"({skipped} excluded: suspect GT or no findings):")
    print(f"  any file hit:      {_rate([r['any_file_hit'] for r in clean])}")
    print(f"  any function hit:  {_rate([r['any_function_hit'] for r in clean])}"
          "   (over runs where GT names functions)")
    print(f"  any line hit:      {_rate([r['any_line_hit'] for r in clean])}")
    print(f"  top-confidence finding hits file: "
          f"{_rate([r['top_conf_file_hit'] for r in clean])}")

    clean_f = [f for f in finding_rows if not f["gt_suspect"]]
    print(f"\nFinding-level precision ({len(clean_f)} findings, non-suspect GT):")
    print(f"  file hit:  {_rate([f['file_hit'] for f in clean_f])}")
    print(f"  line hit:  {_rate([f['line_hit'] for f in clean_f])}")

    print("\nCalibration (finding-level file hit rate by stated confidence):")
    by_conf: dict[float, list] = {}
    for f in clean_f:
        if f["confidence"] is not None:
            by_conf.setdefault(f["confidence"], []).append(f["file_hit"])
    for conf in sorted(by_conf):
        hits = by_conf[conf]
        print(f"  conf={conf:g}: {_rate(hits)}")
    print("=" * 78)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DB_PATH, help="path to runs SQLite db")
    ap.add_argument("--line-tol", type=int, default=DEFAULT_LINE_TOL,
                    help="max distance (lines) still counted as a line hit")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    try:
        if not conn.execute("SELECT name FROM sqlite_master "
                            "WHERE name='ground_truth'").fetchone():
            raise SystemExit("no ground_truth table - run ground_truth.py first")
        finding_rows, run_rows = evaluate(conn, args.line_tol)
        store(conn, finding_rows, run_rows)
        print_report(finding_rows, run_rows)
    finally:
        conn.close()


if __name__ == "__main__":
    main()


# --- tests (run via test runner or pytest) -----------------------------------
def test_norm_function():
    assert norm_function("NDPLayer::toString") == "toString"
    assert norm_function("toString(const char *)") == "toString"
    assert norm_function("a::b::c") == "c"
    assert norm_function(None) is None
    assert norm_function("") is None


def test_match_file():
    assert match_file("valid.c", ["fuzz/api.c", "valid.c"]) == ("exact", "valid.c")
    assert match_file("/src/libxml2/valid.c", ["valid.c"]) == ("suffix", "valid.c")
    assert match_file("icc_codec.cc", ["lib/jxl/icc_codec_common.cc"]) == ("none", None)
    assert match_file("other/parser.c", ["src/parser.c"])[0] == "basename"


def test_parse_lines():
    assert parse_lines(["267-272", "1678", 90]) == [(267, 272), (1678, 1678), (90, 90)]
    assert parse_lines(["bogus", "12 - 14"]) == [(12, 14)]
    assert parse_lines(None) == []


def test_range_distance():
    assert range_distance([(10, 20)], [15]) == 0
    assert range_distance([(10, 20)], [25, 100]) == 5
    assert range_distance([(10, 20), (90, 95)], [100]) == 5
    assert range_distance([], [5]) is None
    assert range_distance([(1, 2)], []) is None


def test_score_finding_hit():
    gt = {
        "suspect_fix": 0,
        "files": [{"path": "libavcodec/cfhd.c", "kind": "code"}],
        "hunks": [{"file": "libavcodec/cfhd.c", "function": "cfhd_decode",
                   "old_changed_lines": [670, 671, 695]}],
    }
    f = {"file": "libavcodec/cfhd.c", "method": "cfhd_decode",
         "lines": ["672", "696"], "confidence_score": 95}
    rec = score_finding(f, gt, line_tol=10)
    assert rec["file_match"] == "exact"
    assert rec["function_hit"] == 1
    assert rec["line_distance"] == 1 and rec["line_hit"] == 1


def test_score_finding_no_gt_functions():
    gt = {
        "suspect_fix": 0,
        "files": [{"path": "parser.c", "kind": "code"}],
        "hunks": [{"file": "parser.c", "function": None,
                   "old_changed_lines": [5000]}],
    }
    f = {"file": "parser.c", "method": "xmlParseComment",
         "lines": ["5092"], "confidence_score": 95}
    rec = score_finding(f, gt, line_tol=10)
    assert rec["file_hit"] == 1
    assert rec["function_hit"] is None     # GT has no function names
    assert rec["line_hit"] == 0 and rec["line_distance"] == 92


def test_score_finding_miss():
    gt = {
        "suspect_fix": 0,
        "files": [{"path": "src/numeric.c", "kind": "code"}],
        "hunks": [{"file": "src/numeric.c", "function": "int_ceil",
                   "old_changed_lines": [100]}],
    }
    f = {"file": "mrbgems/mruby-bigint/core/bigint.c", "method": "mrb_bint_neg",
         "lines": ["1678"], "confidence_score": 93}
    rec = score_finding(f, gt, line_tol=10)
    assert rec["file_hit"] == 0
    assert rec["function_hit"] == 0
    assert rec["line_hit"] == 0
