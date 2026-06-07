"""command_analysis.py

Parse and analyze the shell commands an agent executed during each run, as
stored in the ``run_events`` table of ``arvo_loc_runs.db``.

Each ``tool_use`` event in ``run_events`` holds the agent's Bash invocation in
``event_text`` formatted as::

    command: <cmd> \\ndescription: <human description>

Almost every command is wrapped in ``docker exec vulnscan <inner>`` (the agent
operates on the vulnerability container). This module strips that wrapper,
classifies the inner command by *action* (read / search / list / edit / build /
test / vcs / navigate / other), and extracts the files it touched, the line
ranges it read, and the search pattern it looked for.

Public entry point::

    from command_analysis import analyze
    events_df, runs_df = analyze("arvo_loc_runs.db")

``events_df`` is one row per parsed command; ``runs_df`` is a per-run feature
vector intended to feed downstream clustering of effective vs. ineffective runs.

Run as a script (``python command_analysis.py``) to print a descriptive report.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sqlite3
from collections import Counter
from typing import Optional

import numpy as np
import pandas as pd

DB_PATH = "../arvo_loc_runs.db"

# --- action taxonomy --------------------------------------------------------
READ = "read"          # view file contents (sed -n, cat, head, tail, xxd, ...)
SEARCH = "search"      # grep / rg / find for a pattern
LIST = "list"          # ls / tree directory listing
EDIT = "edit"          # modify the tree (sed -i, patch, tee, git apply, cp, ...)
BUILD = "build"        # arvo compile, make, gcc, ...
TEST = "test"          # arvo (run the PoC/fuzzer)
VCS = "vcs"            # git diff / show / log / blame (inspecting history)
NAVIGATE = "navigate"  # cd / pwd
OTHER = "other"        # wc, awk, which, diff, python, ...
UNKNOWN_TOOL = "unknown_tool"  # tool_use event with empty text (Edit/Write/Grep tool — name not recorded by the parser)

_READ_PROGS = {"cat", "head", "tail", "less", "more", "nl",
               "xxd", "od", "strings", "hexdump", "readelf", "nm"}
_SEARCH_PROGS = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "ripgrep", "find"}
_LIST_PROGS = {"ls", "tree", "dir", "stat"}
_BUILD_PROGS = {"make", "cmake", "gcc", "g++", "clang", "clang++", "cc",
                "ninja", "bear", "configure"}
_EDIT_PROGS = {"tee", "cp", "mv", "dd", "patch", "touch", "truncate"}
_NAV_PROGS = {"cd", "pushd", "popd", "pwd"}

# Source / build / data extensions we treat as "files" when token-matching.
_EXTS = (
    "c h cc cpp cxx hpp hh hxx inc ipp cs m mm y yy l ll s asm java kt "
    "py js ts go rs rb php pl lua xml json yaml yml toml ini cfg conf "
    "patch diff txt md rst cmake mk mak am ac in sh bash sql proto def "
    "map ld td tbl gperf html htm css"
).split()
_EXT_SET = set(_EXTS)

# token that looks like a path ending in a known extension (a/ b/ diff prefixes kept, normalized later)
_FILE_TOKEN_RE = re.compile(r"^[\w./+@-]+\.([A-Za-z0-9+]{1,6})$")
# fallback regex for when shlex cannot tokenize (heredocs, unbalanced quotes)
_FILE_SCAN_RE = re.compile(r"[\w./+@-]*\.[A-Za-z0-9+]{1,6}")
# sed line ranges:  'A,Bp'  or  'Np'
_RANGE_RE = re.compile(r"(\d+)\s*,\s*(\d+)\s*p")
_SINGLE_LINE_RE = re.compile(r"(?<![\d,])(\d+)\s*p\b")
# top-level shell separators
_SHELL_OP_RE = re.compile(r"[|;&]|>>|>|<<|<")


# --- low-level command parsing ---------------------------------------------
def _strip_docker_wrapper(cmd: str) -> tuple[str, Optional[str], str]:
    """Return (wrapper_label, container, inner_command).

    ``docker exec [-i] <container> <inner>``  ->  ('docker', container, inner)
    anything else                             ->  ('local', None, cmd)
    """
    tokens = cmd.split()
    if len(tokens) >= 3 and tokens[0] == "docker" and tokens[1] == "exec":
        i = 2
        while i < len(tokens) and tokens[i].startswith("-"):
            i += 1
        if i < len(tokens):
            container = tokens[i]
            inner = cmd.split(container, 1)[1].strip()
            return "docker", container, inner
    return "local", None, cmd


def _split_pipeline(inner: str) -> list[str]:
    """Split a command on top-level | && || ; while respecting quotes."""
    segments, buf = [], []
    quote = None
    i = 0
    while i < len(inner):
        ch = inner[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch in "|;&":
            # consume runs of operator chars (||, &&, |, ;)
            segments.append("".join(buf))
            buf = []
            while i + 1 < len(inner) and inner[i + 1] in "|;&":
                i += 1
        else:
            buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return [s.strip() for s in segments if s.strip()]


def _tokenize(segment: str) -> list[str]:
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _unwrap_shell_c(tokens: list[str]) -> Optional[str]:
    """If tokens are `sh -c '<script>'` / `bash -c ...`, return the script."""
    if tokens and tokens[0] in ("sh", "bash", "ash", "zsh"):
        if "-c" in tokens:
            idx = tokens.index("-c")
            if idx + 1 < len(tokens):
                return tokens[idx + 1]
    return None


def _files_from_tokens(tokens: list[str]) -> list[str]:
    out = []
    for tok in tokens:
        m = _FILE_TOKEN_RE.match(tok)
        if m and m.group(1).lower() in _EXT_SET:
            out.append(_normalize_path(tok))
    return out


def _normalize_path(p: str) -> str:
    # drop diff-style a/ b/ prefixes so both sides of a patch map to one file
    if p.startswith(("a/", "b/")):
        p = p[2:]
    return p


def _classify(primary: str, tokens: list[str], inner: str) -> str:
    p = primary
    if p == "sed":
        return EDIT if any(t == "-i" or t.startswith("-i") for t in tokens) else READ
    if p == "awk":
        return READ
    if p == "git":
        sub = next((t for t in tokens[1:] if not t.startswith("-")), "")
        if sub == "apply":
            return EDIT
        return VCS
    if p == "arvo":
        return BUILD if "compile" in tokens else TEST
    if p == "echo":
        return EDIT if (">" in inner or ">>" in inner) else OTHER
    if p in _READ_PROGS:
        return READ
    if p in _SEARCH_PROGS:
        return SEARCH
    if p in _LIST_PROGS:
        return LIST
    if p in _EDIT_PROGS:
        return EDIT
    if p in _BUILD_PROGS:
        return BUILD
    if p in _NAV_PROGS:
        return NAVIGATE
    return OTHER


def _search_pattern(prog: str, tokens: list[str]) -> Optional[str]:
    """Best-effort: the regex argument of a grep/rg invocation."""
    if prog not in _SEARCH_PROGS:
        return None
    skip_next = False
    for tok in tokens[1:]:
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-"):
            # options that consume the following argument
            if tok in ("-e", "-f", "-m", "--include", "--exclude", "-A", "-B", "-C"):
                skip_next = True
            continue
        # first positional that is not a path/file is the pattern
        if _FILE_TOKEN_RE.match(tok) and tok.split(".")[-1].lower() in _EXT_SET:
            continue
        if "/" in tok and not any(c in tok for c in r"\^$.*+?[]()|"):
            continue  # looks like a directory scope
        return tok
    return None


def parse_command(event_text: str) -> dict:
    """Parse one ``run_events.event_text`` (a 'command: ... \\ndescription: ...').

    Returns a dict of structured fields (see module docstring / events_df).
    """
    body = event_text[len("command:"):] if event_text.startswith("command:") else event_text
    if "\ndescription:" in body:
        cmd_part, desc = body.split("\ndescription:", 1)
    else:
        cmd_part, desc = body, ""
    raw_command = cmd_part.strip()
    description = desc.strip()

    wrapper, container, inner = _strip_docker_wrapper(raw_command)

    segments = _split_pipeline(inner)
    has_shell_op = len(segments) > 1 or bool(_SHELL_OP_RE.search(inner))
    is_loop = bool(re.search(r"\b(for|while)\b.*\bdo\b", inner))

    # Expand any `sh -c '<script>'` into the embedded script's segments so the
    # real work (often a sed/grep loop) is what we classify.
    expanded: list[list[str]] = []
    scan_text = inner
    for seg in segments:
        toks = _tokenize(seg)
        if not toks:
            continue
        script = _unwrap_shell_c(toks)
        if script:
            scan_text += " " + script
            for sub in _split_pipeline(script):
                st = _tokenize(sub)
                if st:
                    expanded.append(st)
        else:
            expanded.append(toks)

    programs = [t[0] for t in expanded if t]
    # primary program = first non-navigation program (so `cd x && grep` -> grep)
    primary = next((p for p in programs if p not in _NAV_PROGS), programs[0] if programs else "")

    action = _classify(primary, _tokens_for(primary, expanded), inner)

    # files: token-based across all expanded sub-commands, with regex fallback
    files: list[str] = []
    for toks in expanded:
        files.extend(_files_from_tokens(toks))
    if not files:  # heredocs / quoting that broke tokenization
        files = [_normalize_path(m) for m in _FILE_SCAN_RE.findall(scan_text)
                 if m.split(".")[-1].lower() in _EXT_SET]
    files = _dedupe(files)

    # line ranges (sed reads) and total lines viewed
    ranges = [(int(a), int(b)) for a, b in _RANGE_RE.findall(scan_text)]
    singles = [int(n) for n in _SINGLE_LINE_RE.findall(scan_text)]
    lines_read = sum(b - a + 1 for a, b in ranges) + len(singles)

    pattern = _search_pattern(primary, _tokens_for(primary, expanded))

    return {
        "wrapper": wrapper,
        "container": container,
        "raw_command": raw_command,
        "description": description,
        "primary_program": primary,
        "programs": programs,
        "action": action,
        "files": files,
        "n_files": len(files),
        "line_ranges": ranges,
        "lines_read": lines_read,
        "search_pattern": pattern,
        "has_shell_op": has_shell_op,
        "is_loop": is_loop,
    }


def _tokens_for(primary: str, expanded: list[list[str]]) -> list[str]:
    for toks in expanded:
        if toks and toks[0] == primary:
            return toks
    return expanded[0] if expanded else []


def _dedupe(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# --- dataframe builders -----------------------------------------------------
def _run_metadata(conn: sqlite3.Connection) -> pd.DataFrame:
    runs = pd.read_sql_query("SELECT run_id, run_mode, vuln_id FROM runs", conn)
    try:
        arvo = pd.read_sql_query("SELECT localId AS vuln_id, project FROM arvo", conn)
        runs = runs.merge(arvo, on="vuln_id", how="left")
    except Exception:
        runs["project"] = None
    try:
        patch = pd.read_sql_query(
            "SELECT run_id, is_crash_resolved, loc_source FROM patch_data", conn)
        runs = runs.merge(patch, on="run_id", how="left")
    except Exception:
        runs["is_crash_resolved"] = None
        runs["loc_source"] = None
    # has_loc_context: True if the patch run was given root-cause localization
    # context (loc_source is a run_id), False if only the crash output (''),
    # NA for loc runs (no patch_data row). Nearly all runs resolve the crash, so
    # this context split is the meaningful axis for comparison, not is_crash_resolved.
    def _ctx(s):
        if s is None or (isinstance(s, float) and pd.isna(s)):
            return pd.NA
        return len(str(s).strip()) > 0
    runs["has_loc_context"] = runs["loc_source"].map(_ctx).astype("boolean")
    return runs


def _canonicalize_files(df: pd.DataFrame) -> pd.DataFrame:
    """Collapse relative and absolute references to the same file within a run.

    Agents alternate between ``/src/proj/parser.c`` and a bare ``parser.c`` once
    their shell cwd is the project dir. We map each relative path to the unique
    absolute path that shares its basename (leaving it untouched when the
    basename is absent or ambiguous within that run).
    """
    canon_by_run = {}
    for run_id, g in df.groupby("run_id"):
        canon, ambiguous = {}, set()
        for files in g["files"]:
            for f in files:
                if f.startswith("/"):
                    b = f.rsplit("/", 1)[-1]
                    if b in canon and canon[b] != f:
                        ambiguous.add(b)
                    canon[b] = f
        canon_by_run[run_id] = (canon, ambiguous)

    def remap(row):
        canon, ambiguous = canon_by_run[row["run_id"]]
        res = []
        for f in row["files"]:
            b = f.rsplit("/", 1)[-1]
            if not f.startswith("/") and b in canon and b not in ambiguous:
                res.append(canon[b])
            else:
                res.append(f)
        return _dedupe(res)

    df = df.copy()
    df["files"] = df.apply(remap, axis=1)
    df["n_files"] = df["files"].apply(len)
    return df


def build_events_df(conn: sqlite3.Connection) -> pd.DataFrame:
    """One row per parsed agent command, enriched with run metadata."""
    raw = pd.read_sql_query(
        "SELECT run_id, event_num, event_text, event_usage "
        "FROM run_events WHERE event_type = 'tool_use' "
        "AND event_text LIKE 'command:%' ORDER BY run_id, event_num",
        conn,
    )
    parsed = raw["event_text"].apply(parse_command).apply(pd.Series)
    df = pd.concat([raw.drop(columns=["event_text"]), parsed], axis=1)
    df = _canonicalize_files(df)

    # pull output tokens per event as an effort proxy
    df["output_tokens"] = df["event_usage"].apply(_usage_field("output_tokens"))
    df = df.drop(columns=["event_usage"])

    meta = _run_metadata(conn)
    df = df.merge(meta, on="run_id", how="left")
    return df


def _usage_field(field):
    def get(s):
        if not s:
            return 0
        try:
            return json.loads(s).get(field, 0) or 0
        except Exception:
            return 0
    return get


def parse_result_json(rj: Optional[str], run_mode: str, run_id: str) -> dict:
    """Extract features from a run's final answer (``runs.result_json``).

    The agent's deliverable lives here, not in ``run_events``: patch runs emit
    ``{status, patches:[{file, diff}]}``; loc runs emit
    ``{status, vulnerabilities:[{file, method, lines, confidence_score, ...}]}``.
    """
    rec = {
        "run_id": run_id,
        "result_status": None,
        "result_has_output": False,
        "n_result_items": 0,
        "n_result_files": 0,
        "result_files": [],          # basenames, for overlap with investigation
        "patch_n_hunks": 0,
        "patch_added_lines": 0,
        "patch_removed_lines": 0,
        "loc_mean_confidence": np.nan,
        "loc_n_line_refs": 0,
        "root_cause_chars": 0,
    }
    if not rj or rj in ("", "{}", "null"):
        return rec
    try:
        d = json.loads(rj)
    except (json.JSONDecodeError, TypeError):
        return rec
    if not isinstance(d, dict):
        return rec

    rec["result_status"] = d.get("status")
    files = []

    if run_mode == "patch":
        patches = d.get("patches") or []
        rec["n_result_items"] = len(patches)
        for p in patches:
            f = p.get("file")
            if f:
                files.append(_normalize_path(f).rsplit("/", 1)[-1])
            for line in (p.get("diff") or "").splitlines():
                if line.startswith("@@"):
                    rec["patch_n_hunks"] += 1
                elif line.startswith("+") and not line.startswith("+++"):
                    rec["patch_added_lines"] += 1
                elif line.startswith("-") and not line.startswith("---"):
                    rec["patch_removed_lines"] += 1
    else:  # loc (and anything else with a vulnerabilities array)
        vulns = d.get("vulnerabilities") or []
        rec["n_result_items"] = len(vulns)
        confs = []
        for v in vulns:
            f = v.get("file")
            if f:
                files.append(_normalize_path(f).rsplit("/", 1)[-1])
            rec["loc_n_line_refs"] += len(v.get("lines") or [])
            if v.get("confidence_score") is not None:
                confs_val = v.get("confidence_score")
                if isinstance(confs_val, (int, float)):
                    confs.append(confs_val)
            rec["root_cause_chars"] += len(v.get("root_cause_summary") or "")
        if confs:
            rec["loc_mean_confidence"] = round(sum(confs) / len(confs), 1)

    files = _dedupe(files)
    rec["result_files"] = files
    rec["n_result_files"] = len(files)
    rec["result_has_output"] = rec["n_result_items"] > 0
    return rec


def _result_features(conn: sqlite3.Connection) -> pd.DataFrame:
    df = pd.read_sql_query("SELECT run_id, run_mode, result_json FROM runs", conn)
    recs = [parse_result_json(r.result_json, r.run_mode, r.run_id)
            for r in df.itertuples()]
    return pd.DataFrame(recs)


def build_runs_df(events_df: pd.DataFrame, conn: sqlite3.Connection) -> pd.DataFrame:
    """Per-run feature vector for clustering."""
    meta = _run_metadata(conn)

    # raw event-type counts per run (incl. thinking/text and empty tool_use)
    ev = pd.read_sql_query(
        "SELECT run_id, event_type, event_text FROM run_events", conn)
    ev["empty_tool"] = (ev["event_type"] == "tool_use") & (
        ev["event_text"].fillna("").str.strip() == "")
    type_counts = ev.pivot_table(
        index="run_id", columns="event_type", aggfunc="size", fill_value=0)
    type_counts = type_counts.rename(columns={
        "thinking": "n_thinking", "text": "n_text", "tool_use": "n_tool_use"})
    unknown_tool = ev.groupby("run_id")["empty_tool"].sum().rename("n_unknown_tool")

    rows = []
    touched_basenames: dict[str, set] = {}
    for run_id, g in events_df.groupby("run_id"):
        actions = g["action"].value_counts().to_dict()
        touched_basenames[run_id] = {
            f.rsplit("/", 1)[-1] for fs in g["files"] for f in fs}
        files_read = _dedupe([f for fs in g.loc[g.action == READ, "files"] for f in fs])
        files_edited = _dedupe([f for fs in g.loc[g.action == EDIT, "files"] for f in fs])
        all_files = [f for fs in g["files"] for f in fs]
        file_touches = Counter(all_files)
        distinct = len(file_touches)
        n_read = actions.get(READ, 0)
        n_search = actions.get(SEARCH, 0)
        top_file, top_touches = (file_touches.most_common(1)[0]
                                 if file_touches else (None, 0))
        rows.append({
            "run_id": run_id,
            "n_commands": len(g),
            "n_read": n_read,
            "n_search": n_search,
            "n_list": actions.get(LIST, 0),
            "n_edit": actions.get(EDIT, 0),
            "n_build": actions.get(BUILD, 0),
            "n_test": actions.get(TEST, 0),
            "n_vcs": actions.get(VCS, 0),
            "n_navigate": actions.get(NAVIGATE, 0),
            "n_other": actions.get(OTHER, 0),
            "n_distinct_files": distinct,
            "n_file_touches": len(all_files),
            "n_files_read": len(files_read),
            "n_files_edited": len(files_edited),
            "lines_read_total": int(g["lines_read"].sum()),
            "mean_read_span": round(g.loc[g.action == READ, "lines_read"].mean(), 1)
            if n_read else 0.0,
            "read_to_search": round(n_read / n_search, 2) if n_search else float(n_read),
            "depth_reads_per_file": round(n_read / distinct, 2) if distinct else 0.0,
            "frac_loops": round(g["is_loop"].mean(), 3),
            "frac_shell_ops": round(g["has_shell_op"].mean(), 3),
            "top_file": top_file,
            "top_file_touches": top_touches,
            "agent_output_tokens": int(g["output_tokens"].sum()),
        })

    cmd_df = pd.DataFrame(rows)

    # Base on every run that has events (so command-less degenerate runs survive
    # as zero-activity rows for clustering), then left-join command features.
    base = type_counts.reset_index()[["run_id"]].merge(meta, on="run_id", how="left")
    runs_df = base.merge(cmd_df, on="run_id", how="left")
    runs_df = runs_df.merge(type_counts, on="run_id", how="left")
    runs_df = runs_df.merge(unknown_tool, on="run_id", how="left")

    count_cols = [c for c in runs_df.columns if c.startswith("n_")] + [
        "lines_read_total", "top_file_touches", "agent_output_tokens"]
    runs_df[count_cols] = runs_df[count_cols].fillna(0).astype(int)
    float_cols = ["mean_read_span", "read_to_search", "depth_reads_per_file",
                  "frac_loops", "frac_shell_ops"]
    runs_df[float_cols] = runs_df[float_cols].fillna(0.0)
    runs_df["compiled"] = runs_df["n_build"] > 0
    runs_df["edited"] = runs_df["n_edit"] > 0

    # Join final-answer features from result_json and tie the two data sources
    # together: did the agent actually read the files it patched/localized?
    res = _result_features(conn)
    runs_df = runs_df.merge(res, on="run_id", how="left")

    def _overlap(row):
        rf = row["result_files"] if isinstance(row["result_files"], list) else []
        if not rf:
            return np.nan
        touched = touched_basenames.get(row["run_id"], set())
        return round(sum(1 for f in rf if f in touched) / len(rf), 3)

    runs_df["result_files_investigated_frac"] = runs_df.apply(_overlap, axis=1)

    res_int_cols = ["n_result_items", "n_result_files", "patch_n_hunks",
                    "patch_added_lines", "patch_removed_lines",
                    "loc_n_line_refs", "root_cause_chars"]
    runs_df[res_int_cols] = runs_df[res_int_cols].fillna(0).astype(int)
    runs_df["result_has_output"] = runs_df["result_has_output"].fillna(False).astype(bool)
    return runs_df


def analyze(db_path: str = DB_PATH) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Parse all runs. Returns (events_df, runs_df)."""
    conn = sqlite3.connect(db_path)
    try:
        events_df = build_events_df(conn)
        runs_df = build_runs_df(events_df, conn)
    finally:
        conn.close()
    return events_df, runs_df


# --- descriptive report -----------------------------------------------------
def print_report(events_df: pd.DataFrame, runs_df: pd.DataFrame) -> None:
    line = "=" * 64
    print(line)
    print(f"Parsed {len(events_df)} commands across {events_df.run_id.nunique()} runs "
          f"({(runs_df.run_mode == 'loc').sum()} loc, "
          f"{(runs_df.run_mode == 'patch').sum()} patch)")
    print(line)

    print("\nAction distribution (all commands):")
    for action, n in events_df["action"].value_counts().items():
        print(f"  {n:5}  {action}")

    print("\nTop programs:")
    for prog, n in events_df["primary_program"].value_counts().head(12).items():
        print(f"  {n:5}  {prog}")

    # Aggregate cross-run by basename: some runs cd into the project and only
    # ever use relative paths, so the same file appears under several spellings.
    print("\nMost-referenced files (by basename, across runs):")
    by_base, rep_path = Counter(), {}
    for fs in events_df["files"]:
        for f in fs:
            b = f.rsplit("/", 1)[-1]
            by_base[b] += 1
            if f.startswith("/"):
                rep_path.setdefault(b, f)
    for b, n in by_base.most_common(15):
        print(f"  {n:5}  {rep_path.get(b, b)}")

    print("\nPer-run feature summary (median):")
    feats = ["n_commands", "n_read", "n_search", "n_distinct_files",
             "read_to_search", "depth_reads_per_file", "lines_read_total"]
    for mode in ["loc", "patch"]:
        sub = runs_df[runs_df.run_mode == mode]
        if sub.empty:
            continue
        print(f"  [{mode}] " + "  ".join(
            f"{f}={sub[f].median():g}" for f in feats))

    print("\nResult-json (final answer) features by mode (median):")
    for mode, cols in [("loc", ["n_result_items", "n_result_files",
                                "loc_n_line_refs", "root_cause_chars",
                                "result_files_investigated_frac"]),
                       ("patch", ["n_result_items", "n_result_files",
                                  "patch_n_hunks", "patch_added_lines",
                                  "result_files_investigated_frac"])]:
        sub = runs_df[(runs_df.run_mode == mode) & runs_df.result_has_output]
        if sub.empty:
            continue
        print(f"  [{mode} n={len(sub)}] " + "  ".join(
            f"{c}={sub[c].median():g}" for c in cols))

    # Primary comparison: patch runs WITH root-cause localization context vs
    # those given only the crash output (is_crash_resolved barely varies).
    patch = runs_df[(runs_df.run_mode == "patch") & runs_df.has_loc_context.notna()]
    if not patch.empty:
        print("\nPatch runs by localization context (median features):")
        cmp_cols = ["n_commands", "n_read", "n_search", "n_distinct_files",
                    "lines_read_total", "patch_n_hunks", "patch_added_lines",
                    "agent_output_tokens"]
        for val, tag in [(True, "WITH context "), (False, "NO context   ")]:
            grp = patch[patch.has_loc_context == val]
            if grp.empty:
                continue
            print(f"  [{tag} n={len(grp)}] " + "  ".join(
                f"{f}={grp[f].median():g}" for f in cmp_cols))
    print(line)


# --- clustering scaffold ----------------------------------------------------
# Default feature set: investigation behaviour shared by loc and patch runs.
# (result_json features are mode-specific, so they're opt-in per analysis.)
DEFAULT_CLUSTER_FEATURES = [
    "n_commands", "n_read", "n_search", "n_list", "n_edit", "n_vcs",
    "n_distinct_files", "n_file_touches", "lines_read_total", "mean_read_span",
    "read_to_search", "depth_reads_per_file", "frac_shell_ops",
    "n_thinking", "n_text", "agent_output_tokens",
]


def _feature_matrix(runs_df, features, scale):
    feats = [f for f in (features or DEFAULT_CLUSTER_FEATURES) if f in runs_df.columns]
    X = runs_df[feats].apply(pd.to_numeric, errors="coerce").fillna(0.0).to_numpy(float)
    if scale:
        from sklearn.preprocessing import StandardScaler
        X = StandardScaler().fit_transform(X)
    return X, feats


def suggest_k(runs_df, features=None, ks=range(2, 8), scale=True, random_state=0):
    """Silhouette score per k to help choose the cluster count."""
    from sklearn.cluster import KMeans
    from sklearn.metrics import silhouette_score
    X, _ = _feature_matrix(runs_df, features, scale)
    scores = {}
    for k in ks:
        if k >= len(X):
            break
        labels = KMeans(n_clusters=k, n_init=10,
                        random_state=random_state).fit_predict(X)
        scores[k] = round(silhouette_score(X, labels), 3)
    return scores


def cluster_runs(runs_df, features=None, k=4, method="kmeans",
                 scale=True, random_state=0):
    """Cluster runs on their behavioural features.

    Returns (clustered_df, feature_list). ``method`` is 'kmeans' or 'agglomerative'.
    Cluster on a single run_mode at a time for interpretable groups (loc and
    patch behave differently); pass ``runs_df[runs_df.run_mode=='patch']``.
    """
    X, feats = _feature_matrix(runs_df, features, scale)
    if method == "kmeans":
        from sklearn.cluster import KMeans
        model = KMeans(n_clusters=k, n_init=10, random_state=random_state)
    elif method == "agglomerative":
        from sklearn.cluster import AgglomerativeClustering
        model = AgglomerativeClustering(n_clusters=k)
    else:
        raise ValueError(f"unknown method: {method}")
    out = runs_df.copy()
    out["cluster"] = model.fit_predict(X)
    return out, feats


def profile_clusters(clustered, features):
    """Per-cluster summary: size, mode mix, resolved rate, median features."""
    profiles = []
    for cl, g in clustered.groupby("cluster"):
        row = {"cluster": cl, "n_runs": len(g)}
        row["pct_patch"] = round((g.run_mode == "patch").mean() * 100, 0)
        # composition by localization context (the primary comparison axis)
        ctx = g[g.has_loc_context.notna()]
        row["n_with_ctx"] = int((ctx.has_loc_context == True).sum())
        row["n_no_ctx"] = int((ctx.has_loc_context == False).sum())
        row["pct_with_ctx"] = (round((ctx.has_loc_context == True).mean() * 100, 0)
                               if len(ctx) else np.nan)
        for f in features:
            if f in g.columns:
                row[f"med_{f}"] = round(g[f].median(), 2)
        profiles.append(row)
    return pd.DataFrame(profiles)


def print_clusters(runs_df, k, mode="all", method="kmeans", features=None):
    sub = runs_df if mode == "all" else runs_df[runs_df.run_mode == mode]
    sub = sub[sub.n_commands > 0]  # drop degenerate command-less runs
    if len(sub) <= k:
        print(f"\n[cluster] not enough runs ({len(sub)}) for k={k} in mode='{mode}'")
        return
    print("\n" + "=" * 64)
    print(f"Clustering {len(sub)} '{mode}' runs into k={k} ({method})")
    print("silhouette by k:", suggest_k(sub, features))
    clustered, feats = cluster_runs(sub, features=features, k=k, method=method)
    prof = profile_clusters(clustered, feats)
    with pd.option_context("display.width", 200, "display.max_columns", 40):
        print(prof.to_string(index=False))
    print("=" * 64)
    return clustered


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DB_PATH, help="path to runs SQLite db")
    ap.add_argument("--events-csv", help="optional: write per-command rows to CSV")
    ap.add_argument("--runs-csv", help="optional: write per-run features to CSV")
    ap.add_argument("--cluster", type=int, metavar="K",
                    help="also cluster runs into K groups and print profiles")
    ap.add_argument("--mode", choices=["all", "loc", "patch"], default="patch",
                    help="run_mode subset to cluster (default: patch)")
    ap.add_argument("--method", choices=["kmeans", "agglomerative"],
                    default="kmeans", help="clustering algorithm")
    args = ap.parse_args()

    events_df, runs_df = analyze(args.db)
    print_report(events_df, runs_df)

    if args.cluster:
        print_clusters(runs_df, k=args.cluster, mode=args.mode, method=args.method)

    if args.events_csv:
        out = events_df.copy()
        for col in ("programs", "files", "line_ranges"):
            out[col] = out[col].apply(json.dumps)
        out.to_csv(args.events_csv, index=False)
        print(f"wrote {args.events_csv}")
    if args.runs_csv:
        runs_df.to_csv(args.runs_csv, index=False)
        print(f"wrote {args.runs_csv}")


if __name__ == "__main__":
    main()
