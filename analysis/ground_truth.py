"""ground_truth.py

Fetch and structure the ground-truth fix for every vulnerability referenced by
the ``runs`` table, storing the result in a ``ground_truth`` table of the same
database. Downstream patch/localization evaluation joins against this table.

For each distinct ``runs.vuln_id`` the script:

1. Downloads the fix commit as a plain-text patch. The ``arvo`` table's
   ``patch_url`` points at a commit page on GitHub / GitLab / Gitea / gitweb,
   all of which serve the raw patch at a derivable URL (e.g. ``<url>.patch``).
   If every HTTP candidate fails, it falls back to a blob-less ``git clone``
   of ``repo_addr`` and ``git show <commit>``.
2. Parses the unified diff into per-file, per-hunk records: changed line
   ranges on the *old* (vulnerable) side — directly comparable to the line
   numbers agents report, since the pre-fix tree is what they investigated —
   plus the enclosing function from the ``@@ ... @@ <context>`` header.

Note: ``patch_url`` occasionally names a different commit than ``fix_commit``
(ARVO's bisection result). The located patch is what ARVO verified, so the
``patch_url`` commit is fetched as ground truth and ``commit_mismatch`` is set.

Run::

    python ground_truth.py [--db ../arvo_loc_runs.db] [--vuln ID] [--force]

Schema of the resulting ``ground_truth`` table::

    vuln_id          INTEGER PRIMARY KEY
    project          TEXT
    fix_commit       TEXT     -- arvo.fix_commit
    patch_commit     TEXT     -- commit actually fetched (from patch_url)
    commit_mismatch  INTEGER  -- 1 when the two differ
    source           TEXT     -- URL or 'git:<repo>' the diff came from
    fetched_at       TEXT     -- ISO timestamp
    commit_message   TEXT     -- subject line(s) when available
    gt_diff          TEXT     -- full unified diff text
    n_files / n_code_files / n_hunks / added_lines / removed_lines  INTEGER
    suspect_fix      INTEGER  -- 1 when the diff touches no shipped code at all
                              -- (only tests/CI/docs): ARVO's recorded commit
                              -- is then almost certainly not the real fix
    files_json       TEXT     -- [{path, status, kind, n_hunks, added, removed}]
    functions_json   TEXT     -- sorted enclosing-function names (code files)
    hunks_json       TEXT     -- per-hunk records, see _parse_diff()
    error            TEXT     -- non-NULL when the fetch failed
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = "../arvo_loc_runs.db"
HTTP_TIMEOUT = 30
# GitHub rejects requests without a User-Agent.
HTTP_HEADERS = {"User-Agent": "arvo-ground-truth-fetcher"}

# Extensions that can carry shipped code. Interpreter projects (mruby, php,
# quickjs) ship .rb/.php/.js library code, so scripting extensions count too;
# the test/CI path filter below is what separates them from test files.
_SOURCE_EXTS = {
    "c", "h", "cc", "cpp", "cxx", "hpp", "hh", "hxx", "inc", "ipp",
    "m", "mm", "y", "l", "s", "asm", "rs", "go", "rb", "js", "py", "php",
}
# Path fragments marking files that are not shipped code (tests, CI, docs).
_NON_CODE_PATH_RE = re.compile(
    r"(^|/)(tests?|testing|unittests?|test_suite|ci)(/|$)"
    r"|^\.github/|(^|/)docs?(/|$)|(^|/)examples?(/|$)", re.IGNORECASE)


def classify_path(path: str) -> str:
    """'code' for shipped source, 'test_infra' for test/CI/doc paths,
    'other' for everything else (build files, data, ...)."""
    if _NON_CODE_PATH_RE.search(path):
        return "test_infra"
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return "code" if ext in _SOURCE_EXTS else "other"


# --- fetch ------------------------------------------------------------------
def patch_url_candidates(patch_url: str) -> list[str]:
    """Plain-text patch URLs to try, in order, for a commit-page URL."""
    url = patch_url.strip().rstrip("/")
    # gitweb: .../commitdiff/<hash>  ->  .../commitdiff_plain/<hash>
    if "/commitdiff/" in url:
        return [url.replace("/commitdiff/", "/commitdiff_plain/")]
    # GitHub / GitLab / Gitea all serve <commit-url>.patch and .diff
    return [url + ".patch", url + ".diff"]


def http_get(url: str) -> str:
    req = urllib.request.Request(url, headers=HTTP_HEADERS)
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="replace")


def fetch_via_http(patch_url: str) -> tuple[str, str]:
    """Return (diff_text, source_url). Raises the last error if all fail."""
    last_err: Exception = RuntimeError("no candidate URLs")
    for url in patch_url_candidates(patch_url):
        try:
            text = http_get(url)
            if "@@" in text or text.startswith(("diff ", "From ")):
                return text, url
            last_err = ValueError(f"response from {url} does not look like a patch")
        except (urllib.error.URLError, OSError, ValueError) as e:
            last_err = e
    raise last_err


def fetch_via_git(repo_addr: str, commit: str, cache_dir: Path) -> tuple[str, str]:
    """Blob-less clone (cached per repo) + ``git show`` of the fix commit."""
    name = re.sub(r"[^\w.-]+", "_", repo_addr)
    repo_dir = cache_dir / name
    if not (repo_dir / ".git").exists():
        subprocess.run(
            ["git", "clone", "--filter=blob:none", "--no-checkout",
             repo_addr, str(repo_dir)],
            check=True, capture_output=True, text=True, timeout=600)
    show = subprocess.run(
        ["git", "-C", str(repo_dir), "show", "--format=Subject: %s%n",
         "--patch", commit],
        capture_output=True, text=True, timeout=120)
    if show.returncode != 0:
        # commit may be on an unfetched ref; try fetching it explicitly
        subprocess.run(["git", "-C", str(repo_dir), "fetch", "origin", commit],
                       capture_output=True, text=True, timeout=300)
        show = subprocess.run(
            ["git", "-C", str(repo_dir), "show", "--format=Subject: %s%n",
             "--patch", commit],
            check=True, capture_output=True, text=True, timeout=120)
    return show.stdout, f"git:{repo_addr}"


def commit_from_patch_url(patch_url: str) -> str | None:
    m = re.search(r"([0-9a-f]{12,40})\s*$", patch_url.strip().rstrip("/"))
    return m.group(1) if m else None


# --- parse ------------------------------------------------------------------
_DIFF_GIT_RE = re.compile(r'^diff --git (?:"?a/(.*?)"?) (?:"?b/(.*?)"?)$')
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@ ?(.*)$")
# identifier directly before '(' in the hunk's section header, e.g.
# "static int xmlParseInternal(xmlParserCtxt *ctxt," -> xmlParseInternal
_FUNC_RE = re.compile(r"([A-Za-z_~][A-Za-z0-9_:~]*)\s*\(")


def _function_from_section(section: str) -> str | None:
    matches = _FUNC_RE.findall(section)
    return matches[-1] if matches else None


def _subject(diff_text: str) -> str:
    """Commit subject from format-patch / git-show headers, if present."""
    lines = []
    for line in diff_text[:4000].splitlines():
        if line.startswith("Subject:"):
            subj = re.sub(r"^Subject:\s*(\[PATCH[^\]]*\]\s*)?", "", line)
            lines.append(subj.strip())
        elif lines:
            # format-patch wraps long subjects with indented continuations
            if line.startswith((" ", "\t")):
                lines.append(line.strip())
            else:
                break
    return " ".join(lines)


def _parse_diff(diff_text: str) -> dict:
    """Structure a unified diff.

    Returns ``{files: [...], hunks: [...], functions: [...], added, removed}``
    where each hunk record carries the old-side (vulnerable version) and
    new-side line positions::

        {file, status, section, function,
         old_start, old_len, new_start, new_len,
         added, removed, old_changed_lines, new_changed_lines}

    ``old_changed_lines`` are old-side line numbers of '-' lines; for hunks
    that only add code, the old-side anchor line is used so every hunk maps
    to at least one pre-fix location.
    """
    files: list[dict] = []
    hunks: list[dict] = []
    cur_file: dict | None = None
    cur_hunk: dict | None = None
    old_ln = new_ln = 0

    def close_hunk():
        nonlocal cur_hunk
        if cur_hunk is not None:
            if not cur_hunk["old_changed_lines"]:
                cur_hunk["old_changed_lines"] = [cur_hunk["old_start"]]
            hunks.append(cur_hunk)
            cur_hunk = None

    for line in diff_text.splitlines():
        m = _DIFF_GIT_RE.match(line)
        if m:
            close_hunk()
            old_path, new_path = m.group(1), m.group(2)
            path = new_path if new_path != "/dev/null" else old_path
            cur_file = {
                "path": path,
                "old_path": old_path,
                "status": "modified",
                "kind": classify_path(path),
                "n_hunks": 0,
                "added": 0,
                "removed": 0,
            }
            files.append(cur_file)
            continue
        if cur_file is not None and cur_hunk is None:
            if line.startswith("new file"):
                cur_file["status"] = "added"
            elif line.startswith("deleted file"):
                cur_file["status"] = "deleted"
            elif line.startswith("rename from"):
                cur_file["status"] = "renamed"
        m = _HUNK_RE.match(line)
        if m and cur_file is not None:
            close_hunk()
            old_start = int(m.group(1))
            new_start = int(m.group(3))
            section = m.group(5).strip()
            cur_hunk = {
                "file": cur_file["path"],
                "status": cur_file["status"],
                "section": section,
                "function": _function_from_section(section),
                "old_start": old_start,
                "old_len": int(m.group(2) or 1),
                "new_start": new_start,
                "new_len": int(m.group(4) or 1),
                "added": 0,
                "removed": 0,
                "old_changed_lines": [],
                "new_changed_lines": [],
            }
            cur_file["n_hunks"] += 1
            old_ln, new_ln = old_start, new_start
            continue
        if cur_hunk is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            cur_hunk["added"] += 1
            cur_file["added"] += 1
            cur_hunk["new_changed_lines"].append(new_ln)
            new_ln += 1
        elif line.startswith("-") and not line.startswith("---"):
            cur_hunk["removed"] += 1
            cur_file["removed"] += 1
            cur_hunk["old_changed_lines"].append(old_ln)
            old_ln += 1
        elif line.startswith("\\"):  # "\ No newline at end of file"
            pass
        elif line.startswith((" ", "")) and not line.startswith(
                ("diff ", "index ", "--- ", "+++ ")):
            # context line; blank lines inside hunks arrive as "" over HTTP
            old_ln += 1
            new_ln += 1
    close_hunk()

    kind_by_file = {f["path"]: f["kind"] for f in files}
    for h in hunks:
        h["kind"] = kind_by_file.get(h["file"], "other")
    functions = sorted({h["function"] for h in hunks
                        if h["function"] and h["kind"] == "code"})
    return {
        "files": files,
        "hunks": hunks,
        "functions": functions,
        "added": sum(f["added"] for f in files),
        "removed": sum(f["removed"] for f in files),
    }


# --- db ---------------------------------------------------------------------
DDL = """
CREATE TABLE IF NOT EXISTS ground_truth (
    vuln_id         INTEGER PRIMARY KEY,
    project         TEXT,
    fix_commit      TEXT,
    patch_commit    TEXT,
    commit_mismatch INTEGER,
    source          TEXT,
    fetched_at      TEXT,
    commit_message  TEXT,
    gt_diff         TEXT,
    n_files         INTEGER,
    n_code_files    INTEGER,
    n_hunks         INTEGER,
    added_lines     INTEGER,
    removed_lines   INTEGER,
    suspect_fix     INTEGER,
    files_json      TEXT,
    functions_json  TEXT,
    hunks_json      TEXT,
    error           TEXT
)
"""


def ensure_table(conn: sqlite3.Connection) -> None:
    """Create ground_truth; the table is fully regenerable, so on a schema
    change just drop and rebuild (rows refetch on the next run)."""
    expected = set(re.findall(r"^\s{4}(\w+)", DDL, re.MULTILINE))
    existing = {r[1] for r in conn.execute(
        "PRAGMA table_info(ground_truth)").fetchall()}
    if existing and existing != expected:
        print("ground_truth schema changed; rebuilding table")
        conn.execute("DROP TABLE ground_truth")
    conn.execute(DDL)
    conn.commit()


def vulns_to_fetch(conn: sqlite3.Connection, only_vuln: int | None,
                   force: bool) -> list[sqlite3.Row]:
    q = """
        SELECT DISTINCT a.localId AS vuln_id, a.project, a.repo_addr,
               a.fix_commit, a.patch_url
        FROM arvo a JOIN runs r ON r.vuln_id = a.localId
    """
    args: list = []
    if only_vuln is not None:
        q += " WHERE a.localId = ?"
        args.append(only_vuln)
    rows = conn.execute(q + " ORDER BY a.project", args).fetchall()
    if force or only_vuln is not None:
        return rows
    done = {r[0] for r in conn.execute(
        "SELECT vuln_id FROM ground_truth WHERE gt_diff IS NOT NULL")}
    return [r for r in rows if r["vuln_id"] not in done]


def store(conn: sqlite3.Connection, rec: dict) -> None:
    cols = ", ".join(rec)
    ph = ", ".join("?" * len(rec))
    conn.execute(
        f"INSERT OR REPLACE INTO ground_truth ({cols}) VALUES ({ph})",
        list(rec.values()))
    conn.commit()


def fetch_one(row: sqlite3.Row, cache_dir: Path, allow_git: bool) -> dict:
    vuln_id = row["vuln_id"]
    patch_commit = commit_from_patch_url(row["patch_url"] or "") or row["fix_commit"]
    rec = {
        "vuln_id": vuln_id,
        "project": row["project"],
        "fix_commit": row["fix_commit"],
        "patch_commit": patch_commit,
        "commit_mismatch": int(bool(
            row["fix_commit"] and patch_commit
            and not patch_commit.startswith(row["fix_commit"])
            and not row["fix_commit"].startswith(patch_commit))),
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": None, "commit_message": None, "gt_diff": None,
        "n_files": 0, "n_code_files": 0, "n_hunks": 0,
        "added_lines": 0, "removed_lines": 0, "suspect_fix": None,
        "files_json": None, "functions_json": None, "hunks_json": None,
        "error": None,
    }

    diff_text = source = None
    errors = []
    if row["patch_url"]:
        try:
            diff_text, source = fetch_via_http(row["patch_url"])
        except Exception as e:
            errors.append(f"http: {e}")
    if diff_text is None and allow_git and row["repo_addr"]:
        try:
            diff_text, source = fetch_via_git(
                row["repo_addr"], patch_commit, cache_dir)
        except Exception as e:
            errors.append(f"git: {e}")
    if diff_text is None:
        rec["error"] = "; ".join(errors) or "no patch_url or repo_addr"
        return rec

    parsed = _parse_diff(diff_text)
    if not parsed["hunks"]:
        rec["error"] = f"fetched from {source} but parsed 0 hunks"
        rec["gt_diff"] = diff_text
        rec["source"] = source
        return rec

    n_code = sum(f["kind"] == "code" for f in parsed["files"])
    rec.update({
        "source": source,
        "commit_message": _subject(diff_text) or None,
        "gt_diff": diff_text,
        "n_files": len(parsed["files"]),
        "n_code_files": n_code,
        "n_hunks": len(parsed["hunks"]),
        "added_lines": parsed["added"],
        "removed_lines": parsed["removed"],
        "suspect_fix": int(n_code == 0),
        "files_json": json.dumps(parsed["files"]),
        "functions_json": json.dumps(parsed["functions"]),
        "hunks_json": json.dumps(parsed["hunks"]),
    })
    return rec


# --- report -----------------------------------------------------------------
def print_summary(conn: sqlite3.Connection) -> None:
    rows = conn.execute("""
        SELECT vuln_id, project, commit_mismatch, n_files, n_code_files,
               n_hunks, added_lines, removed_lines, suspect_fix,
               files_json, functions_json, error
        FROM ground_truth ORDER BY project, vuln_id
    """).fetchall()
    print("=" * 78)
    ok = sum(1 for r in rows if not r["error"])
    suspect = sum(1 for r in rows if r["suspect_fix"])
    print(f"ground_truth: {ok}/{len(rows)} vulns with a parsed fix diff"
          + (f", {suspect} SUSPECT (no code changed)" if suspect else ""))
    print("=" * 78)
    for r in rows:
        if r["error"]:
            print(f"{r['vuln_id']:>12}  {r['project']:<14} ERROR: {r['error']}")
            continue
        funcs = json.loads(r["functions_json"] or "[]")
        flags = ""
        if r["commit_mismatch"]:
            flags += "  [commit!=fix_commit]"
        if r["suspect_fix"]:
            flags += "  [SUSPECT: no code files]"
        print(f"{r['vuln_id']:>12}  {r['project']:<14} "
              f"files={r['n_files']}({r['n_code_files']} code) "
              f"hunks={r['n_hunks']} +{r['added_lines']}/-{r['removed_lines']}"
              f"{flags}")
        if r["suspect_fix"]:
            paths = [f["path"] for f in json.loads(r["files_json"] or "[]")]
            print(f"{'':>12}  touches: {', '.join(paths[:4])}")
        elif funcs:
            print(f"{'':>12}  functions: {', '.join(funcs[:6])}"
                  f"{' ...' if len(funcs) > 6 else ''}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DB_PATH, help="path to runs SQLite db")
    ap.add_argument("--vuln", type=int, help="fetch a single vuln_id")
    ap.add_argument("--force", action="store_true",
                    help="re-fetch vulns already in ground_truth")
    ap.add_argument("--no-git-fallback", action="store_true",
                    help="skip the git-clone fallback (HTTP only)")
    ap.add_argument("--cache-dir", default=None,
                    help="directory for fallback git clones "
                         "(default: system temp)")
    args = ap.parse_args()

    cache_dir = Path(args.cache_dir) if args.cache_dir else (
        Path(tempfile.gettempdir()) / "arvo_gt_repos")
    cache_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    try:
        ensure_table(conn)
        todo = vulns_to_fetch(conn, args.vuln, args.force)
        if not todo:
            print("nothing to fetch (use --force to re-fetch)")
        for row in todo:
            print(f"fetching {row['vuln_id']} ({row['project']}) ...",
                  end=" ", flush=True)
            rec = fetch_one(row, cache_dir, allow_git=not args.no_git_fallback)
            store(conn, rec)
            print(f"FAILED: {rec['error']}" if rec["error"] else
                  f"ok ({rec['n_hunks']} hunks via {rec['source']})")
        print()
        print_summary(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()


# --- tests (python -m pytest analysis/ground_truth.py) -----------------------
_SAMPLE_PATCH = """\
From 1e9d69f89679435d8dc5f59d30d68f117b422821 Mon Sep 17 00:00:00 2001
From: Dev <dev@example.com>
Subject: [PATCH] codegen.c: should not call mrb_free() for
 reallocated buffer

diff --git a/mrbgems/mruby-compiler/core/codegen.c b/mrbgems/mruby-compiler/core/codegen.c
index 1111111..2222222 100644
--- a/mrbgems/mruby-compiler/core/codegen.c
+++ b/mrbgems/mruby-compiler/core/codegen.c
@@ -100,7 +100,6 @@ static void codegen_error(codegen_scope *s)
   if (!s) return;
-  mrb_free(s->mrb, s->iseq);
   while (s->prev) {
     codegen_scope *tmp = s->prev;
+    mrb_free(s->mrb, tmp->iseq);
     s = tmp;
   }
diff --git a/test/t.rb b/test/t.rb
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/test/t.rb
@@ -0,0 +1,2 @@
+assert('regression') do
+end
"""


def test_parse_sample_patch():
    p = _parse_diff(_SAMPLE_PATCH)
    assert [f["path"] for f in p["files"]] == [
        "mrbgems/mruby-compiler/core/codegen.c", "test/t.rb"]
    assert p["files"][0]["kind"] == "code"
    assert p["files"][1]["kind"] == "test_infra"
    assert p["files"][1]["status"] == "added"
    assert p["functions"] == ["codegen_error"]
    h = p["hunks"][0]
    assert h["old_start"] == 100 and h["removed"] == 1 and h["added"] == 1
    # '-  mrb_free...' is the 2nd line of the hunk -> old-side line 101
    assert h["old_changed_lines"] == [101]
    assert h["new_changed_lines"] == [103]
    # add-only hunks still anchor to an old-side line
    assert p["hunks"][1]["old_changed_lines"]
    assert p["added"] == 3 and p["removed"] == 1


def test_classify_path():
    assert classify_path("src/parser.c") == "code"
    assert classify_path("mrbgems/mruby-complex/mrblib/complex.rb") == "code"
    assert classify_path("sapi/fuzzer/fuzzer-sapi.c") == "code"
    assert classify_path("tests/oss-fuzz.sh") == "test_infra"
    assert classify_path(".github/workflows/lint.yml") == "test_infra"
    assert classify_path("tests/unit/capi/GEOSIntersectionTest.cpp") == "test_infra"
    assert classify_path("README.md") == "other"
    assert classify_path("CMakeLists.txt") == "other"


def test_subject_wrapping():
    assert _subject(_SAMPLE_PATCH) == (
        "codegen.c: should not call mrb_free() for reallocated buffer")


def test_url_candidates():
    gh = patch_url_candidates(
        "https://github.com/mruby/mruby/commit/abc123")
    assert gh[0].endswith(".patch")
    gw = patch_url_candidates(
        "https://git.ffmpeg.org/gitweb/ffmpeg.git/commitdiff/abc123")
    assert gw == ["https://git.ffmpeg.org/gitweb/ffmpeg.git/commitdiff_plain/abc123"]


def test_commit_from_patch_url():
    assert commit_from_patch_url(
        "https://github.com/x/y/commit/2fb0d735b433a7") == "2fb0d735b433a7"
    assert commit_from_patch_url("https://github.com/x/y") is None
