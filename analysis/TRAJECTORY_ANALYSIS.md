# Run Trajectory & Narrative Characterization

Specification for `trajectory_analysis.py`, which characterizes each run from
its turn-by-turn `run_events` stream — the agent's *thinking*, narration
*text*, and *tool calls* in order — rather than from aggregate totals. It is
the content/sequence companion to `command_analysis.py` (which it reuses for
shell-command parsing) and feeds a `run_characterization` table that joins to
the `loc_eval`/`patch_eval` outcome tables.

| | |
|---|---|
| input | `runs`, `run_events` (+ `patch_eval`, `loc_eval_runs` if present) |
| output table | `run_characterization` (one row per run, replaced each run) |
| reuses | `command_analysis.parse_command` and its action taxonomy |
| run | `python trajectory_analysis.py [--db ../arvo_loc_runs.db] [--csv out.csv] [--no-store]` |
| inspect one run | `python trajectory_analysis.py --narrative <run_id>` |

---

## 1. Why `run_events`, and what's in it

`run_events` holds 3,170 rows across 77 runs, one row per agent turn-event,
ordered by `event_num`, typed as:

| `event_type` | count | what it carries |
|---|---|---|
| `thinking` | 646 | the agent's private reasoning (median ~1,100 chars, up to ~30k) |
| `text` | 880 | narration to the user, including `★ Insight` callout blocks |
| `tool_use` | 1,644 | a tool call; for shell calls, `event_text` is `command: <cmd>\ndescription: <desc>` |

Two facts established by inspection drive the design:

- **`runs.agent_thought_log` / `agent_insight_log` are not substitutes.** They
  are short summaries (hundreds–few thousand chars); the full granular
  reasoning lives only in `run_events`. So the turn stream is the right source.
- **Every run ends in a `text` event** (77/77) — the final answer narration.
  The deliverable itself (patch diff / localization JSON) is in
  `runs.result_json`, not in `run_events`; this script characterizes the
  *process*, while `loc_eval`/`patch_eval` score the *product*.
- **13 of 1,644 `tool_use` events have empty text.** These are Edit/Write/Grep
  tool calls (not shell commands). Consequently patch *application* is mostly
  invisible here — patch agents emit their diff via `result_json`, and when
  they do edit in-container they often use the Edit tool, not `sed -i`. So
  trajectory milestones are reliable for **investigation** actions
  (read/search/build/test) but **not** for the edit step (see caveats).

---

## 2. What the script computes

### a. Reasoning markers (content of thinking + text)

`detect_markers(text)` runs six curated regexes over every thinking/text
event. Patterns are deliberately multi-word to suppress false positives — bare
`still`/`again`/`wait` are too noisy to count, so e.g. backtracking requires
`wait` to be followed by `,` `.` or em-dash (catching "Wait, that's wrong" but
not "wait for the build").

| marker | captures | signal |
|---|---|---|
| `verify` | verify / confirm / double-check / sanity check / make sure | rigor, self-checking |
| `backtrack` | wait, / actually, / reconsider / I was wrong / scratch that / let me rethink | self-correction, course changes |
| `root_cause` | root cause / underlying cause / actual bug / why does | depth of causal reasoning |
| `hypothesis` | hypothesis / I suspect / my theory / probably because | explicit hypothesis framing |
| `deadend` | doesn't work / still crashes / build fail / no luck | recognized failed attempts |
| `insight` | `★` or the word `Insight` | the agent's own structured callouts |

For each marker the script records a per-run **count** and the **normalized
positions** (0=start … 1=end) where it fired, condensed into
`backtrack_mean_pos` (early vs. late course-correction).

### b. Trajectory milestones (sequence of events)

Tool-use events are parsed with `command_analysis.parse_command` to get an
action (read/search/list/edit/build/test/…) per command, then:

- `orient_frac` — fraction of the run before the *first* tool call (how long
  spent reading the crash log / planning before acting).
- `first_edit_pos`, `first_build_pos`, `first_test_pos` — position of the first
  command of each action as a fraction of the run.
- `investigation_before_edit` — count of read/search commands before the first
  shell edit (depth before committing to a change).

### c. Rut / stuck signals

`rut_score` is the **fraction of four independent pathology flags that fire**,
each thresholded against the cohort's tail (so normal investigation isn't
penalized). This replaced an earlier weighted formula that mislabeled ~67% of
runs "stuck" because re-reading different regions of one file looked like
"no progress":

| flag | fires when | rationale |
|---|---|---|
| `looping` | `max_consecutive_repeat >= 3` | the *same* command (program+action+files+line-ranges) back-to-back ≥3× |
| `repetitive` | `max_cmd_repeats >= 6` | the same command issued ≥6× total across the run |
| `thrashing` | `backtrack_density >= 0.30` | heavy self-correction relative to reasoning volume |
| `stalled` | `max_no_progress_streak >= 25` | extreme run of tool calls surfacing no new file (only the tail; median is 9, which is normal depth) |

`rut_score ∈ {0, .25, .5, .75, 1}`; `rut_flags` stores which fired.
Command identity collapses absolute/relative path spellings by basename so
`/src/p/parser.c` and `parser.c` count as one file.

### d. Archetype (rule-based, cohort-relative)

`assign_archetypes` labels each run; thresholds are percentiles of the active
cohort, so labels adapt to the dataset instead of hard-coded constants. First
match wins:

| archetype | rule | reading |
|---|---|---|
| `degenerate` | `n_commands == 0` | empty / aborted run (≤ a couple events) |
| `stuck` | `rut_score >= 0.5` (≥2 flags) | genuine thrashing |
| `methodical` | high `verify_density` (≥p70) + `n_events ≥ median` + low rut | verification-heavy, sustained |
| `direct` | `n_events ≤ p25` + low backtracking | short, decisive |
| `exploratory` | `distinct_files ≥ p75` | broad file sweep |
| `standard` | otherwise | the unremarkable middle |

---

## 3. `run_characterization` table

One row per run. Identity/metric columns come from `runs`; outcome columns are
left-joined from `patch_eval` and `loc_eval_runs` when those tables exist.

### Identity & run metrics (from `runs`)
| column | meaning |
|---|---|
| `run_id` | primary key |
| `run_mode` | `loc` or `patch` |
| `vuln_id` | ARVO localId |
| `num_turns`, `duration`, `total_cost_usd`, `result_type` | harness-recorded run metrics |

### Event composition
| column | meaning |
|---|---|
| `n_events` | total `run_events` rows for the run |
| `n_thinking` / `n_text` / `n_tool_use` | event-type counts |
| `n_commands` | shell-command tool calls actually parsed (excludes the 13 empty/non-shell tool events) |
| `think_chars_total` / `think_chars_mean` / `think_chars_max` | volume of private reasoning |
| `think_tokens` | output tokens attributed to thinking events (from `event_usage`) |
| `think_to_action` | `n_thinking / n_tool_use` — reasoning per action |

### Reasoning markers
| column | meaning |
|---|---|
| `n_verify`, `n_backtrack`, `n_root_cause`, `n_hypothesis`, `n_deadend`, `n_insight` | per-marker event counts |
| `verify_density` | `n_verify / (n_thinking + n_text)` |
| `backtrack_density` | `n_backtrack / (n_thinking + n_text)` |
| `backtrack_mean_pos` | mean normalized position (0–1) of backtracking events; NULL if none |

### Trajectory milestones
| column | meaning |
|---|---|
| `orient_frac` | fraction of the run before the first tool call |
| `first_edit_pos` / `first_build_pos` / `first_test_pos` | normalized position of the first such command; **often NULL** (esp. edit — see caveats) |
| `investigation_before_edit` | read/search commands before the first shell edit; NULL if no shell edit |
| `distinct_files` | distinct file basenames touched by commands |

### Rut signals
| column | meaning |
|---|---|
| `max_consecutive_repeat` | longest run of an identical command signature |
| `max_cmd_repeats` | max occurrences of any single command signature |
| `max_no_progress_streak` | longest streak of commands surfacing no new file basename |
| `rut_flags` | `\|`-joined names of the flags that fired |
| `rut_score` | fraction of the four flags that fired (0–1) |

### Classification & outcomes
| column | meaning |
|---|---|
| `archetype` | one of degenerate / stuck / methodical / direct / exploratory / standard |
| `agreement` | from `patch_eval` (line/file/divergent/…); NULL for loc runs |
| `patched_at_crash_frame` | from `patch_eval` |
| `has_loc_context` | from `patch_eval` (1 = experiment-1 style, given localization) |
| `loc_best_level` | from `loc_eval_runs` (the run's own loc accuracy, for loc runs) |

---

## 4. The `--narrative` mode

`--narrative <run_id>` prints a header (key marker counts, milestones, rut) and
then **one line per event**: `event_num`, type symbol (`K`=thinking,
`T`=text, `U`=tool_use), coarse phase (`orient` <0.15, `work`, `wrap` >0.85), a
one-line gloss (for commands: action + program + files + line range / search
pattern; for reasoning: the first ~100 chars), and any detected markers in
`«guillemets»`. This is the most direct, human-readable characterization of a
single run — it reconstructs the agent's investigation rhythm at a glance
(e.g. orient → `think→read→think→search→read` loop → wrap-up report).

---

## 5. Analysis performed & top findings

Snapshot 2026-06-24; regenerate by re-running the script. Aggregates exclude
the 3 `degenerate` runs where noted.

**Archetype distribution (77 runs):** standard 31 · stuck 13 · exploratory 10 ·
methodical 10 · direct 10 · degenerate 3. The `stuck` group is dominated by
long localization runs (median 67 events, 16 verifies), not patch runs.

**Reasoning-marker medians (active runs):** verify 7 · backtrack 3 · root_cause
3 · insight 2 · hypothesis 0 · deadend 0. Agents verify and reason about root
cause routinely, explicitly frame hypotheses rarely, and seldom *narrate*
dead-ends (failed attempts show up as backtracking, not as stated failure).

**Orientation is fast:** median `orient_frac` ≈ 0.07 — agents start acting
almost immediately after reading the crash log, rather than planning at length.

### Finding 1 — Verification effort does not buy patch quality
The `methodical` (verification-heavy) archetype skewed **divergent** (6
divergent vs. 1 line-agreement), while plain `standard` runs produced the most
line-agreements (10 line, 4 file, 7 divergent). More self-checking did not
translate into hitting the maintainer's fix site. This is consistent with the
`patch_eval` finding that localization *accuracy*, not patcher effort, drives
agreement — extra verification refines a patch around wherever the agent
already decided to look.

### Finding 2 — "Stuck" and "wrong patch" are independent failure modes
`rut_score` does not separate patch outcomes (median 0.0 across line / file /
divergent agreement). Thrashing concentrates in long *localization* runs, not
in the patch runs that diverge from ground truth. A low-rut run can still
confidently patch the wrong site, and a high-rut run can still land correctly.
Process pathology and product correctness must be measured separately.

### Finding 3 — The reasoning is investigation-shaped, not patch-shaped
Milestone coverage itself is a finding: `first_edit_pos` is populated for only
~8 runs because the edit/patch step largely bypasses the shell. The turn stream
richly documents how agents *investigate* (read/search loops, insight
callouts, root-cause reasoning) but barely documents how they *construct the
fix*. Trajectory analysis is therefore strongest as a lens on the
localization/investigation phase.

---

## 6. Caveats

- **Edit invisibility.** Patch application via the Edit/Write tool leaves an
  empty `tool_use` event, so `first_edit_pos` / `investigation_before_edit` are
  NULL for most patch runs. Don't read their absence as "the agent never
  edited."
- **Marker regexes are heuristic.** They favor precision over recall; counts
  are comparative signals, not exact tallies of cognitive events. `insight`
  keys partly on the `★` glyph, which is formatting-dependent.
- **Small n.** 77 runs (74 active). Archetype × outcome cross-tabs are
  directional, not statistically powered; pair any claim with the per-run
  table rather than a single rate.
- **Thresholds are cohort-relative.** Archetype percentiles and the rut tail
  thresholds were tuned to this dataset; re-tune if the run population changes
  materially.
- **UTF-8 output.** The script forces UTF-8 stdout because run text contains
  `★` and box-drawing characters that crash the default Windows cp1252 console.
```
