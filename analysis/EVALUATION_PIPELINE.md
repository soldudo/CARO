# Run-Trace Evaluation Pipeline

Specifications for the three scripts that score agent localization and patch
runs against the maintainer's known fix ("ground truth"):

| script | input | output table(s) | one-line purpose |
|---|---|---|---|
| `ground_truth.py` | `arvo` + `runs` | `ground_truth` | fetch & structure the real fix commit for every vuln a run touched |
| `loc_eval.py` | `runs.result_json` (loc runs) + `ground_truth` | `loc_eval`, `loc_eval_runs` | grade localization findings at file / function / line granularity |
| `patch_eval.py` | `runs.result_json` (patch runs) + `ground_truth` + `arvo.crash_output` (+ `loc_eval_runs`) | `patch_eval` | grade patch agreement with the fix, crash-site placement, and edit taxonomy |

All three operate on the same SQLite database (default `../arvo_loc_runs.db`
relative to this folder) and are idempotent: `ground_truth.py` skips
already-fetched vulns unless `--force`; the two eval scripts drop and rebuild
their tables on every invocation. Run order matters:

```
python ground_truth.py --db ../arvo_loc_runs.db     # once (network access)
python loc_eval.py     --db ../arvo_loc_runs.db     # before patch_eval if you
python patch_eval.py   --db ../arvo_loc_runs.db     # want the loc->patch join
```

Each script embeds its own unit tests (`test_*` functions at the bottom),
runnable with pytest or a plain loop over `dir(module)`.

---

## Shared conventions

These apply across all three scripts and explain most scoring decisions:

**Old-side line numbers.** Every line-level comparison uses the *old*
(pre-fix) side of the ground-truth diff: the line numbers that fix hunks
removed code from, or anchored to, in the vulnerable tree. That tree is
(approximately) what the agent investigated and edited, so agent-reported
lines and agent hunk positions are directly comparable to ground truth
without checking out any source. Hunks that only *add* lines anchor to their
old-side start line so every hunk maps to at least one pre-fix location.

**Suffix path matching.** Agents report project-relative paths
(`parser.c`, `lib/jxl/icc_codec.cc`) that can differ from the diff's paths
in leading directories. `loc_eval.match_file()` compares normalized paths
(strip `a/`, `b/`, `./`, leading `/`) at three quality levels:
`exact` > `suffix` (one path ends with the other) > `basename` (same
filename only). Anything at `basename` or better counts as a file hit;
the match kind is recorded so basename-only matches can be audited.

**NULL means unknowable, 0 means miss.** When a measurement cannot be made
(ground truth exposes no function names; the run produced no patch; no crash
frames parsed), the column is NULL and the run is excluded from that
metric's denominator. A 0 always means the comparison was made and failed.

**Suspect ground truth.** Vulns whose recorded fix commit touches no shipped
code (`ground_truth.suspect_fix = 1`) are still scored, but every downstream
row carries `gt_suspect` and the printed aggregates exclude them.

**Tolerances are recorded.** `loc_eval` and `patch_eval` rows store the
`line_tol` / `frame_tol` they were scored under, so the tables are
self-describing after a re-run with different thresholds.

---

## 1. ground_truth.py

### What it does

For each distinct `runs.vuln_id`, joined to `arvo` for `fix_commit`,
`patch_url`, and `repo_addr`:

1. **Fetch** the fix commit as plain text. The commit-page `patch_url` is
   rewritten to a raw-patch URL by host pattern: GitHub / GitLab / Gitea
   commit URLs get `.patch` (then `.diff`) appended; gitweb URLs
   (`.../commitdiff/<hash>`) become `commitdiff_plain`. If every HTTP
   candidate fails, it falls back to a blob-less
   `git clone --filter=blob:none --no-checkout` of `repo_addr` (cached per
   repo under `--cache-dir`, default system temp) and `git show <commit>`.
2. **Choose the commit.** ARVO occasionally records a `fix_commit` that
   differs from the commit named in `patch_url`. The `patch_url` commit is
   what ARVO actually located and verified, so it is fetched as ground truth;
   `commit_mismatch = 1` flags the disagreement (2 of 25 current vulns).
3. **Parse** the unified diff into per-file and per-hunk records, including
   the enclosing function from each `@@ ... @@ <context>` header (the last
   identifier before `(`), and classify each path as `code` / `test_infra` /
   `other` (see `classify_path`). Scripting extensions (`.rb`, `.js`, `.py`,
   `.php`) count as code — interpreter projects ship library code in them —
   and the path filter (`tests/`, `.github/`, `docs/`, `ci/`, `examples/`)
   is what separates shipped code from test scaffolding.

### CLI

```
python ground_truth.py [--db PATH] [--vuln ID] [--force]
                       [--no-git-fallback] [--cache-dir DIR]
```

### `ground_truth` table (one row per vuln)

| column | meaning |
|---|---|
| `vuln_id` | `arvo.localId` (primary key) |
| `project` | project name from `arvo` |
| `fix_commit` | commit hash recorded in `arvo.fix_commit` |
| `patch_commit` | hash actually fetched (parsed from `patch_url`, falling back to `fix_commit`) |
| `commit_mismatch` | 1 when `fix_commit` and `patch_commit` name different commits |
| `source` | the URL the diff came from, or `git:<repo>` for the clone fallback |
| `fetched_at` | UTC ISO timestamp of the fetch |
| `commit_message` | subject line(s) recovered from format-patch headers, incl. wrapped continuations |
| `gt_diff` | the full unified diff text, verbatim |
| `n_files` | files touched by the diff |
| `n_code_files` | files classified `code` (shipped source) |
| `n_hunks` | total hunks |
| `added_lines` / `removed_lines` | `+` / `-` line totals across the diff |
| `suspect_fix` | 1 when `n_code_files = 0`: the recorded commit changes only tests/CI/docs and is almost certainly **not** the real fix. 4 of 25 current vulns (mruby 42532183, quickjs 42531506, wasm3 42531785, libtpms 42531667) |
| `files_json` | `[{path, old_path, status (modified/added/deleted/renamed), kind (code/test_infra/other), n_hunks, added, removed}]` |
| `functions_json` | sorted unique enclosing-function names, **code files only** |
| `hunks_json` | per-hunk records: `{file, status, kind, section (raw header text), function, old_start, old_len, new_start, new_len, added, removed, old_changed_lines [old-side line numbers of '-' lines, or the anchor for add-only hunks], new_changed_lines}` |
| `error` | non-NULL when fetch/parse failed (such rows are ignored downstream) |

### Caveats

- `suspect_fix` rows need hand-correction (find the true fix commit nearby in
  history) before those vulns can be evaluated meaningfully.
- Some fixes are large bundled commits (PcapPlusPlus: 17 files; wolfssl: 33
  hunks); downstream scoring tolerates this by taking minima over hunks, but
  function/file *Jaccard*-style metrics will look artificially low there.
- Line numbers can drift if commits landed between the ARVO vulnerable
  snapshot and the fix commit's parent. Distances near the tolerance
  boundary, and the recurring distance-136 cluster (libxml2 42528951),
  deserve a manual look before being treated as misses.

---

## 2. loc_eval.py

### What it does

Parses every loc run's final answer (`runs.result_json`, shape
`{status, vulnerabilities: [{file, method, lines, confidence_score,
root_cause_summary}]}`) and scores each reported finding against the
ground-truth hunks at three granularities:

- **file** — `match_file()` against all GT paths (any kind, so a finding
  pointing at a test file the fix touched still registers; code-only
  filtering happens at analysis time via `hunks_json.kind`).
- **function** — reported `method`, normalized by stripping parameter lists
  and C++ qualifiers (`NDPLayer::toString` → `toString`), compared with the
  normalized enclosing functions of GT hunks *in the matched file*. NULL
  when those hunks expose no function names (git provides no context header,
  e.g. some C++ headers) — unknowable, not a miss.
- **line** — reported `lines` entries (`"267-272"`, `"1678"`, or bare ints)
  parsed to ranges; `line_distance` = minimum distance between any reported
  range and any `old_changed_lines` entry of the matched file's hunks
  (0 = overlap); `line_hit` thresholds at `--line-tol` (default 10).

Interpretation caveat: ground truth is where the *maintainer's fix landed*,
which is not always the only defensible root-cause location. A miss means
"did not point at the fix site," not necessarily "wrong."

### CLI

```
python loc_eval.py [--db PATH] [--line-tol N]
```

### `loc_eval` table (one row per reported finding)

| column | meaning |
|---|---|
| `run_id`, `vuln_id`, `finding_idx` | key; `finding_idx` is the position in the `vulnerabilities` array |
| `confidence` | the finding's `confidence_score` as stated by the agent |
| `reported_file` / `reported_method` / `reported_lines` | the agent's claim, verbatim (`reported_lines` is the raw JSON list) |
| `file_match` | `exact` \| `suffix` \| `basename` \| `none` |
| `file_hit` | 1 if `file_match != none` |
| `matched_gt_file` | the GT path it matched |
| `function_hit` | 1/0, or NULL when GT names no functions for that file |
| `matched_gt_function` | normalized function name on a hit |
| `line_distance` | min distance to a GT-changed old-side line in the matched file; NULL if no file match or no line info |
| `line_hit` | `line_distance <= line_tol`; NULL when unknowable |
| `line_tol` | tolerance the row was scored under |
| `gt_suspect` | copied from `ground_truth.suspect_fix` |

### `loc_eval_runs` table (one row per loc run)

| column | meaning |
|---|---|
| `run_id`, `vuln_id`, `project` | key + context |
| `n_findings` | findings in the run's final JSON (0 for empty `{}` results) |
| `result_status` | the run's reported `status` (e.g. `LOCALIZED`) |
| `any_file_hit` / `any_line_hit` | 1 if any finding hit at that level |
| `any_function_hit` | same, but NULL when *no* finding could be function-scored |
| `best_level` | finest granularity achieved: `line` > `function` > `file` > `none` |
| `top_conf_file_hit` | `file_hit` of the single highest-confidence finding — measures whether the agent's *best bet* was right, vs. shotgunning |
| `mean_confidence` | mean stated confidence across findings |
| `findings_hit_frac` | fraction of findings with a file hit — a precision proxy; extra non-hitting findings dilute it |
| `gt_suspect` | as above |

`loc_eval_runs.run_id` matches `patch_data.loc_source`, which is how patch
runs are joined to the accuracy of the localization they were given.

---

## 3. patch_eval.py

### What it does

Parses every patch run's final answer (`{status, patches: [{file, diff}]}`).
Agent diffs are *bare* unified diffs (`--- a/x` / `+++ b/x` / `@@`, no
`diff --git` header), so `parse_agent_diff()` handles them directly, using
the patch entry's `file` field as the authority when headers are absent.
Three measurement groups per run:

**Tier 1 — agreement with the maintainer's fix.** Compared against GT *code*
files only (a doc edit in the real commit can't penalize the agent):
file overlap, minimum hunk-to-fix line distance on the old side, size ratio,
summarized into the ordinal `agreement` grade.

**Crash-site placement.** `parse_crash_frames()` extracts the *first* stack
of the sanitizer report in `arvo.crash_output` (the faulting access — a
second `#0` starts the allocation/free stack and stops collection), drops
fuzzer/ASan/libc scaffolding frames, and keeps up to 8 project frames with
their depth (0 = innermost). Both the agent's hunks *and the GT hunks* are
measured against these frames. The superficial-patch signal is the
conjunction: `patched_at_crash_frame = 1` while `gt_at_crash_frame = 0`
(agent patched where it crashed; maintainer fixed somewhere else). Note the
flags are per-run minima over hunks, so a multi-hunk patch can legitimately
be `agreement = line` *and* sit at a crash frame.

**Tier 2 — edit taxonomy.** Each hunk's added lines run through ordered
regexes, first match wins: `alloc_fix` (allocation-call change) →
`init` (zeroing / initialization / memset) → `len_clamp` (MIN/clamp/modulo)
→ `bounds_check` (guard with comparison, early return, goto-fail) →
`type_change` (width/signedness keywords) → `delete_only` (no added lines)
→ `other`. Deliberately coarse: its job is separating defensive edits from
semantic ones, not a complete ontology.

### CLI

```
python patch_eval.py [--db PATH] [--line-tol N] [--frame-tol N]
```

Both tolerances default to 10 lines.

### `patch_eval` table (one row per patch run)

| column | meaning |
|---|---|
| `run_id`, `vuln_id`, `project`, `experiment_id` | key + experiment context |
| `has_loc_context` | 1 when `patch_data.loc_source` names a localization run whose output was provided to the patcher (experiment-1 style); 0 for env-only baselines (experiment 2) |
| `loc_source` | that localization run's `run_id`, or NULL |
| `loc_best_level` | the loc source's `best_level` from `loc_eval_runs` — the column that enables the loc-accuracy → patch-quality cross-tab |
| `is_crash_resolved` | from `patch_data` (currently sparse) |
| `result_status` | the run's reported status (`PATCH_READY`, or NULL for empty results) |
| `n_patch_files` / `n_patch_hunks` | size of the agent's patch set |
| `added_lines` / `removed_lines` | totals over agent hunks |
| `file_jaccard` | \|matched files\| / \|union of agent files and GT code files\| — penalizes both missing the fix's files and patching extra ones |
| `n_common_files` | agent files that suffix-matched a GT code file |
| `file_hit` | 1 if any agent file matched; NULL when no GT code files exist |
| `min_gt_line_distance` | min distance between agent hunk changed lines and GT `old_changed_lines` over shared files; NULL if no shared file |
| `gt_line_hit` | `min_gt_line_distance <= line_tol` |
| `size_ratio` | agent (added+removed) / GT code (added+removed). \<1 = more minimal than the maintainer; \>1 = larger rewrite |
| `agreement` | `line` \| `file` \| `divergent` (patch exists, zero file overlap) \| `no_patch` (empty result) \| `no_gt` (suspect GT, nothing to compare) |
| `dominant_category` | most common hunk taxonomy label |
| `category_counts` | JSON `{category: n_hunks}` |
| `agent_min_frame_dist` | min line distance from any agent hunk to a crash frame in the same file |
| `agent_frame_depth` | stack depth of the nearest frame (0 = the crashing line's frame) |
| `patched_at_crash_frame` | `agent_min_frame_dist <= frame_tol`; NULL when no patch or no frames |
| `gt_min_frame_dist` / `gt_at_crash_frame` | the same measurement applied to the ground-truth hunks — the baseline for what a *maintainer* does |
| `gt_suspect` | from `ground_truth.suspect_fix` |
| `line_tol` / `frame_tol` | tolerances this row was scored under |
| `patch_hunks_json` | parsed agent hunks (`{file, old_start, old_len, added, removed, old_changed_lines, added_lines_text}`) — kept so an LLM-judge stage can consume patches without re-parsing |

### Reading the grades together

- `agreement = line` — strong evidence the agent found the maintainer's fix
  site (the observed distance distribution is bimodal: ~0 or ~100+, so the
  tolerance is not doing the work).
- `agreement = divergent` + `patched_at_crash_frame = 1` + `gt_at_crash_frame
  = 0` — the symptomatic-patch profile; first candidates for hand labeling.
- `agreement = divergent` + off-frame — could be an alternative valid fix or
  a confused one; mechanical metrics cannot distinguish, this is the bucket
  for the LLM-judge tier.
- `size_ratio` extremes qualify everything above (a 0.03 guard vs. a 6.0
  rewrite are different failure modes even at the same agreement level).

---

## Snapshot of results (2026-06-11, line_tol = frame_tol = 10)

Recorded here for orientation; regenerate by re-running the scripts.

- `ground_truth`: 25/25 vulns fetched (all via HTTP), 4 suspect, 2 commit
  mismatches.
- `loc_eval`: 27 runs / 43 findings. Over 22 usable runs: 55% any-file hit,
  38% function hit (where knowable), 45% line hit. Stated confidence
  (90–97 everywhere) is uncalibrated — hit rate does not rise with it.
- `patch_eval`: 50 runs (43 with patches; 42 scored against non-suspect GT):
  36% line / 14% file / 50% divergent. Line-agreement doubles with
  localization context (48% vs 24%). Context runs whose loc source was
  line-accurate produced line-agreeing patches 10/11; with a wrong loc
  source, 0/10 (baselines on those same vulns also all diverged — shared
  difficulty, not proven misdirection). Agent patches sit at a crash frame
  45% of the time vs. 24% for maintainer fixes; 9 symptomatic suspects
  flagged by run_id in the report output.
