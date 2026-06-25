"""trajectory_analysis.py

Characterize each run from its turn-by-turn ``run_events`` stream — the
agent's thinking, narration text, and tool calls in order — rather than from
aggregate totals alone. Complements command_analysis.py (which it reuses for
parsing the shell commands) by reading the *content* of thinking/text events
and the *sequence* of all events.

Three things come out of one run:

* **Reasoning markers** — verification, self-correction / backtracking,
  root-cause reasoning, hypothesis framing, dead-end recognition, and the
  agent's own ``★ Insight`` callouts — counted over thinking+text events,
  with where in the run they cluster (early vs late).
* **Trajectory shape** — milestone positions (first edit / build / test as a
  fraction of the run), how long the agent orients before acting, and how
  investigation depth precedes the first edit.
* **Rut / stuck signals** — repeated near-identical commands, stretches of
  tool calls that surface no new file, and backtracking density — combined
  into a transparent ``rut_score``.

These feed a rule-based ``archetype`` per run and a ``run_characterization``
table that joins cleanly to loc_eval_runs / patch_eval for "do thrashing runs
produce worse patches?" style questions.

Run::

    python trajectory_analysis.py [--db ../arvo_loc_runs.db] [--csv out.csv]
    python trajectory_analysis.py --narrative <run_id>   # annotated turn log

The ``--narrative`` mode prints one line per event (phase, type, detected
markers, and a gloss) — a direct, readable characterization of a single run.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from collections import Counter

import numpy as np
import pandas as pd

from command_analysis import parse_command, READ, EDIT, BUILD, TEST

DB_PATH = "../arvo_loc_runs.db"


# --- reasoning markers ------------------------------------------------------
# Curated multi-word patterns chosen to keep false positives low (bare "still"
# / "again" are too noisy to count). Each maps to one cognitive category.
_MARKERS = {
    "verify": re.compile(
        r"\b(verif|confirm|double[- ]check|make sure|sanity check|"
        r"let me check|to be sure|cross[- ]check)", re.I),
    "backtrack": re.compile(
        r"(\bwait[,.—]|\bactually[,. ]|let me reconsider|reconsider|"
        r"on second thought|scratch that|i was wrong|that'?s (?:not right|"
        r"wrong|incorrect)|my mistake|let me rethink|i need to re-?(?:think|"
        r"examine|visit)|hold on|never mind)", re.I),
    "root_cause": re.compile(
        r"\b(root cause|underlying (?:cause|bug|issue)|actual (?:bug|cause|"
        r"root)|real (?:bug|cause)|true cause|why (?:does|this|the))", re.I),
    "hypothesis": re.compile(
        r"\b(hypothesis|i suspect|my theory|i (?:believe|think) (?:the|this|"
        r"it)|it'?s likely|probably (?:because|due)|this suggests|"
        r"i'?m guessing|presumably)", re.I),
    "deadend": re.compile(
        r"\b(does(?:n'?t| not) work|did(?:n'?t| not) work|still (?:crash|"
        r"fail|segfault|see)|no luck|that failed|didn'?t help|compilation "
        r"(?:error|fail)|build fail|won'?t (?:compile|build)|unsuccessful)",
        re.I),
    "insight": re.compile(r"(★|\bInsight\b)"),
}


def detect_markers(text: str) -> set[str]:
    t = text or ""
    return {name for name, rx in _MARKERS.items() if rx.search(t)}


def _usage_output_tokens(usage_json: str | None) -> int:
    if not usage_json:
        return 0
    try:
        return int(json.loads(usage_json).get("output_tokens", 0) or 0)
    except (json.JSONDecodeError, TypeError, ValueError):
        return 0


# --- per-run feature extraction ---------------------------------------------
def _cmd_signature(parsed: dict) -> tuple:
    """Identity of a command for repeat detection: program + action + the
    files and line ranges it touched (by basename, so abs/rel spellings of the
    same file collapse)."""
    files = tuple(sorted(f.rsplit("/", 1)[-1] for f in parsed["files"]))
    ranges = tuple(sorted(parsed["line_ranges"]))
    return (parsed["primary_program"], parsed["action"], files, ranges)


def _max_consecutive(sigs: list[tuple]) -> int:
    best = run = 0
    prev = object()
    for s in sigs:
        run = run + 1 if s == prev else 1
        best = max(best, run)
        prev = s
    return best


def extract_run(events: list[sqlite3.Row]) -> dict:
    """Build the feature dict for one run's ordered event list."""
    n = len(events)
    types = [e["event_type"] for e in events]
    n_think = types.count("thinking")
    n_text = types.count("text")
    n_tool = types.count("tool_use")
    reason_events = n_think + n_text

    # --- reasoning markers over thinking+text content ---
    marker_counts = Counter()
    marker_positions: dict[str, list[float]] = {k: [] for k in _MARKERS}
    think_chars: list[int] = []
    think_tokens = 0
    for i, e in enumerate(events):
        if e["event_type"] not in ("thinking", "text"):
            continue
        txt = e["event_text"] or ""
        if e["event_type"] == "thinking":
            think_chars.append(len(txt))
            think_tokens += _usage_output_tokens(e["event_usage"])
        pos = i / (n - 1) if n > 1 else 0.0
        for m in detect_markers(txt):
            marker_counts[m] += 1
            marker_positions[m].append(pos)

    # --- trajectory milestones from tool_use commands ---
    parsed_cmds: list[tuple[int, dict]] = []
    for i, e in enumerate(events):
        if e["event_type"] != "tool_use":
            continue
        txt = e["event_text"] or ""
        if not txt.strip().startswith("command:"):
            continue  # Edit/Write/Grep tool — no command text recorded
        parsed_cmds.append((i, parse_command(txt)))

    def first_pos(action: str) -> float | None:
        for i, p in parsed_cmds:
            if p["action"] == action:
                return round(i / (n - 1), 3) if n > 1 else 0.0
        return None

    first_tool_idx = next((i for i, t in enumerate(types) if t == "tool_use"), None)
    orient_frac = round(first_tool_idx / n, 3) if first_tool_idx is not None else None
    first_edit_pos = first_pos(EDIT)
    # investigation depth: read/search/build commands before the first edit
    first_edit_cmd_idx = next(
        (k for k, (_, p) in enumerate(parsed_cmds) if p["action"] == EDIT), None)
    investigation_before_edit = (
        sum(1 for _, p in parsed_cmds[:first_edit_cmd_idx]
            if p["action"] in (READ, "search"))
        if first_edit_cmd_idx is not None else None)

    # --- rut / stuck signals ---
    sigs = [_cmd_signature(p) for _, p in parsed_cmds]
    max_consecutive_repeat = _max_consecutive(sigs)
    sig_counts = Counter(sigs)
    max_cmd_repeats = max(sig_counts.values()) if sig_counts else 0

    # longest streak of tool commands surfacing no new file basename
    seen: set[str] = set()
    streak = max_streak = 0
    for _, p in parsed_cmds:
        bases = {f.rsplit("/", 1)[-1] for f in p["files"]}
        if bases - seen:
            streak = 0
            seen |= bases
        else:
            streak += 1
            max_streak = max(max_streak, streak)

    backtrack_density = round(marker_counts["backtrack"] / reason_events, 3) \
        if reason_events else 0.0
    verify_density = round(marker_counts["verify"] / reason_events, 3) \
        if reason_events else 0.0

    # rut_score = fraction of independent "stuck" signals that fire, each at a
    # threshold tuned to the cohort's tail (re-reading regions of one file is
    # normal investigation, so plain no-progress is only counted at extremes).
    rut_flags = {
        "looping": int(max_consecutive_repeat >= 3),     # same cmd back-to-back
        "repetitive": int(max_cmd_repeats >= 6),          # same cmd many times
        "thrashing": int(backtrack_density >= 0.30),      # heavy self-correction
        "stalled": int(max_streak >= 25),                 # extreme re-reading
    }
    rut_score = round(sum(rut_flags.values()) / len(rut_flags), 3)

    # where backtracking happens (mean position, 0=start..1=end)
    bt = marker_positions["backtrack"]
    backtrack_mean_pos = round(float(np.mean(bt)), 3) if bt else None

    distinct_files = len({f.rsplit("/", 1)[-1]
                          for _, p in parsed_cmds for f in p["files"]})

    return {
        "n_events": n,
        "n_thinking": n_think,
        "n_text": n_text,
        "n_tool_use": n_tool,
        "n_commands": len(parsed_cmds),
        "think_chars_total": sum(think_chars),
        "think_chars_mean": round(float(np.mean(think_chars)), 0) if think_chars else 0,
        "think_chars_max": max(think_chars) if think_chars else 0,
        "think_tokens": think_tokens,
        "think_to_action": round(n_think / n_tool, 2) if n_tool else None,
        "n_verify": marker_counts["verify"],
        "n_backtrack": marker_counts["backtrack"],
        "n_root_cause": marker_counts["root_cause"],
        "n_hypothesis": marker_counts["hypothesis"],
        "n_deadend": marker_counts["deadend"],
        "n_insight": marker_counts["insight"],
        "verify_density": verify_density,
        "backtrack_density": backtrack_density,
        "backtrack_mean_pos": backtrack_mean_pos,
        "orient_frac": orient_frac,
        "first_edit_pos": first_edit_pos,
        "first_build_pos": first_pos(BUILD),
        "first_test_pos": first_pos(TEST),
        "investigation_before_edit": investigation_before_edit,
        "distinct_files": distinct_files,
        "max_consecutive_repeat": max_consecutive_repeat,
        "max_cmd_repeats": max_cmd_repeats,
        "max_no_progress_streak": max_streak,
        "rut_flags": "|".join(k for k, v in rut_flags.items() if v),
        "rut_score": rut_score,
    }


# --- archetype labelling ----------------------------------------------------
def assign_archetypes(df: pd.DataFrame) -> pd.Series:
    """Rule-based archetype per run, with cohort-relative thresholds so the
    labels adapt to the dataset rather than hard-coded magic numbers."""
    active = df[df["n_commands"] > 0]
    ev_p25 = active["n_events"].quantile(0.25) if len(active) else 0
    vd_p70 = active["verify_density"].quantile(0.70) if len(active) else 0
    df_p75 = active["distinct_files"].quantile(0.75) if len(active) else 0
    ev_med = active["n_events"].median() if len(active) else 0

    def label(r) -> str:
        if r["n_commands"] == 0:
            return "degenerate"          # no tool activity (empty/aborted run)
        if r["rut_score"] >= 0.5:
            return "stuck"               # >=2 independent pathology signals fire
        if r["verify_density"] >= vd_p70 and r["n_events"] >= ev_med \
                and r["rut_score"] < 0.25:
            return "methodical"          # verification-heavy, sustained, low rut
        if r["n_events"] <= ev_p25 and r["backtrack_density"] < 0.1:
            return "direct"              # short, little backtracking
        if r["distinct_files"] >= df_p75:
            return "exploratory"         # broad file sweep
        return "standard"

    return df.apply(label, axis=1)


# --- db / assembly ----------------------------------------------------------
def build_features(conn: sqlite3.Connection) -> pd.DataFrame:
    runs = pd.read_sql_query(
        "SELECT run_id, run_mode, vuln_id, num_turns, duration, "
        "total_cost_usd, result_type FROM runs", conn)
    rows = []
    for run_id in runs["run_id"]:
        events = conn.execute(
            "SELECT event_type, event_text, event_usage FROM run_events "
            "WHERE run_id = ? ORDER BY event_num", (run_id,)).fetchall()
        feat = extract_run(events) if events else extract_run([])
        feat["run_id"] = run_id
        rows.append(feat)
    feats = pd.DataFrame(rows)
    df = runs.merge(feats, on="run_id", how="left")
    df["archetype"] = assign_archetypes(df)

    # optional outcome joins (present only after loc_eval/patch_eval ran)
    for tbl, cols in (("patch_eval", "agreement, patched_at_crash_frame, has_loc_context"),
                      ("loc_eval_runs", "best_level AS loc_best_level")):
        if conn.execute("SELECT name FROM sqlite_master WHERE name=?",
                        (tbl,)).fetchone():
            extra = pd.read_sql_query(f"SELECT run_id, {cols} FROM {tbl}", conn)
            df = df.merge(extra, on="run_id", how="left")
    return df


def store(conn: sqlite3.Connection, df: pd.DataFrame) -> None:
    df.to_sql("run_characterization", conn, if_exists="replace", index=False)
    conn.commit()


# --- narrative (single-run annotated trace) ---------------------------------
def _gloss(event: sqlite3.Row) -> str:
    et, txt = event["event_type"], (event["event_text"] or "")
    if et == "tool_use":
        if not txt.strip().startswith("command:"):
            return "[non-shell tool]"
        p = parse_command(txt)
        bits = [p["action"], p["primary_program"]]
        if p["files"]:
            bits.append(",".join(f.rsplit("/", 1)[-1] for f in p["files"][:3]))
        if p["line_ranges"]:
            bits.append(f"L{p['line_ranges'][0][0]}-{p['line_ranges'][0][1]}")
        if p["search_pattern"]:
            bits.append(f"/{p['search_pattern']}/")
        return "  ".join(str(b) for b in bits if b)
    one_line = re.sub(r"\s+", " ", txt).strip()
    return one_line[:100]


def print_narrative(conn: sqlite3.Connection, run_id: str) -> None:
    events = conn.execute(
        "SELECT event_num, event_type, event_text, event_usage FROM run_events "
        "WHERE run_id = ? ORDER BY event_num", (run_id,)).fetchall()
    if not events:
        print(f"no events for {run_id}")
        return
    feat = extract_run(events)
    n = len(events)
    sym = {"thinking": "K", "text": "T", "tool_use": "U"}
    print("=" * 80)
    print(f"{run_id}   ({n} events, archetype computed from full cohort)")
    print(f"rut={feat['rut_score']}  verify={feat['n_verify']}  "
          f"backtrack={feat['n_backtrack']}  insight={feat['n_insight']}  "
          f"root_cause={feat['n_root_cause']}")
    print(f"first edit@{feat['first_edit_pos']}  build@{feat['first_build_pos']}  "
          f"test@{feat['first_test_pos']}  max no-progress streak="
          f"{feat['max_no_progress_streak']}")
    print("=" * 80)
    for i, e in enumerate(events):
        phase = "orient" if i / n < 0.15 else "wrap" if i / n > 0.85 else "work"
        marks = ",".join(sorted(detect_markers(e["event_text"] or ""))) \
            if e["event_type"] in ("thinking", "text") else ""
        flag = f" «{marks}»" if marks else ""
        print(f"{e['event_num']:>3} {sym[e['event_type']]} {phase:<6} "
              f"{_gloss(e):<70}{flag}")
    print("=" * 80)


# --- report -----------------------------------------------------------------
def print_report(df: pd.DataFrame) -> None:
    line = "=" * 78
    print(line)
    print(f"Characterized {len(df)} runs "
          f"({(df.run_mode == 'loc').sum()} loc, {(df.run_mode == 'patch').sum()} patch)")
    print(line)

    print("\nArchetype distribution:")
    for arch, n in df["archetype"].value_counts().items():
        sub = df[df.archetype == arch]
        print(f"  {arch:<12} {n:>3}   "
              f"med_events={sub.n_events.median():.0f} "
              f"med_rut={sub.rut_score.median():.2f} "
              f"med_verify={sub.n_verify.median():.0f}")

    print("\nReasoning markers (median per run, active runs):")
    act = df[df.n_commands > 0]
    for c in ["n_verify", "n_backtrack", "n_root_cause", "n_hypothesis",
              "n_deadend", "n_insight"]:
        print(f"  {c:<14} median={act[c].median():.0f}  max={act[c].max():.0f}")

    print("\nTrajectory milestones (median fraction of run, patch runs):")
    pr = df[(df.run_mode == "patch") & (df.n_commands > 0)]
    for c in ["orient_frac", "first_edit_pos", "first_build_pos", "first_test_pos"]:
        vals = pr[c].dropna()
        if len(vals):
            print(f"  {c:<16} {vals.median():.2f}  (n={len(vals)})")

    if "agreement" in df.columns:
        print("\nArchetype x patch agreement (count):")
        pe = df[df.agreement.notna() & (df.agreement != "no_patch")]
        if len(pe):
            ct = pd.crosstab(pe.archetype, pe.agreement)
            with pd.option_context("display.width", 200):
                print(ct.to_string())
        print("\nrut_score by patch agreement (median):")
        for ag in ["line", "file", "divergent"]:
            s = pe[pe.agreement == ag]["rut_score"]
            if len(s):
                print(f"  {ag:<10} median rut={s.median():.2f}  (n={len(s)})")
    print(line)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--narrative", metavar="RUN_ID",
                    help="print an annotated turn-by-turn trace for one run")
    ap.add_argument("--csv", help="optional: write per-run features to CSV")
    ap.add_argument("--no-store", action="store_true",
                    help="don't write the run_characterization table")
    args = ap.parse_args()

    try:  # source text carries ★ / box-drawing chars; force UTF-8 output
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    try:
        if args.narrative:
            print_narrative(conn, args.narrative)
            return
        df = build_features(conn)
        if not args.no_store:
            store(conn, df)
        print_report(df)
        if args.csv:
            df.to_csv(args.csv, index=False)
            print(f"wrote {args.csv}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()


# --- tests ------------------------------------------------------------------
def test_detect_markers():
    assert "verify" in detect_markers("Let me verify this assumption")
    assert "backtrack" in detect_markers("Wait, that's not right.")
    assert "backtrack" in detect_markers("Actually, I need to reconsider")
    assert "root_cause" in detect_markers("The root cause is a GC trigger")
    assert "deadend" in detect_markers("That didn't work, still crashes")
    assert "insight" in detect_markers("★ Insight ─── key finding")
    assert detect_markers("plain reading of the file") == set()
    # bare noisy words alone must NOT trigger
    assert "backtrack" not in detect_markers("I will wait for the build")


def test_max_consecutive():
    assert _max_consecutive(["a", "a", "a", "b"]) == 3
    assert _max_consecutive(["a", "b", "a", "b"]) == 1
    assert _max_consecutive([]) == 0


def _ev(t, text="", usage=None):
    return {"event_type": t, "event_text": text, "event_usage": usage}


def test_extract_run_markers_and_rut():
    cmd = "command: docker exec vulnscan sed -n '1,5p' foo.c \ndescription: read"
    events = [
        _ev("text", "I'll start by reading the crash log."),
        _ev("thinking", "The root cause looks like a UAF. Let me verify."),
        _ev("tool_use", cmd),
        _ev("tool_use", cmd),          # exact repeat -> consecutive repeat = 2
        _ev("thinking", "Wait, that's not right. Still crashes."),
        _ev("text", "Final report."),
    ]
    f = extract_run(events)
    assert f["n_commands"] == 2
    assert f["n_verify"] == 1 and f["n_root_cause"] == 1
    assert f["n_backtrack"] == 1 and f["n_deadend"] == 1
    assert f["max_consecutive_repeat"] == 2
    assert f["max_no_progress_streak"] == 1   # 2nd identical read surfaces no new file
    assert f["rut_score"] in (0.0, 0.25, 0.5, 0.75, 1.0)  # flag-fraction


def test_extract_run_empty():
    f = extract_run([])
    assert f["n_events"] == 0 and f["n_commands"] == 0 and f["rut_score"] == 0.0


def test_milestones():
    rd = "command: docker exec vulnscan sed -n '1,5p' a.c \ndescription: read"
    ed = "command: docker exec vulnscan sed -i 's/x/y/' a.c \ndescription: edit"
    events = [_ev("text", "go"), _ev("tool_use", rd), _ev("tool_use", ed)]
    f = extract_run(events)
    assert f["first_edit_pos"] == 1.0          # edit is the last of 3 events
    assert f["investigation_before_edit"] == 1  # one read before the edit
