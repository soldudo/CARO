# CARO: Code agent ARVO experiment Orchestration

**CARO** localization branch readme

### Update 2026-03-18
* Full localization, patching and logging cycle operational.
* Patch markdown files added - copy patch_agent/skill.md to rootainer/opt/agent
* run_parser updated and now sends patch runs to db
* patch_data - new table holds patch run_id, localization source (loc_run_id) and has a column to log if patch resolved crash (and patch crash output)
* run parameters now back to dictionary to support rootainer workers

## Preparation (crash log)
Caro injects a copy of the arvo vulnerability's original crash log from the experiment database.
* **WARNING**  Some entries in the arvo database are missing the original crash log.
* Before running a batch of experiments, verify their crash logs are available in the database.
* If a crash log is missing please use the arvo container to generate a crash log and update the db entry.
* Instructions and script to be added
* NOTE: Some containers may require multiple attempts before a crash successfully occurs. This requires manual review of the generated log. 

## Setup Claude's container (once)
* Build a container from the project's Dockerfile
* `docker build -t claude_dind . `
* Run a claude_dind container named rootainer
* `docker run --privileged --name rootainer -d claude_dind`
* Terminal into rootainer
* `docker exec -it rootainer sh`
* Launch claude and authenticate
* Change settings
* `/config`
* Verbose output - true(false was default)
* Default permission mode - Don't Ask (default was default)
* Output mode - Explanatory (default was default)
* Model - Opus 4.6 High effort (Sonet 4.6 was default)
  <img width="692" height="237" alt="image" src="https://github.com/user-attachments/assets/d27b53e1-29ce-4498-b604-312a2c28d8be" />

* Copy markdown files files to opt/agent/ in rootainer
* `docker cp memory_safety_skills.md rootainer:opt/agent/memory_safety_skills.md`

## Experiment Workflow
* Claude is installed in the rootainer container
* The vulnerable arvo container (vulnscan) is spun up inside the rootainer.
* Claude's agent and skills markdown files include instruction to execute all commands on vulnscan using the command prefix `docker exec vulnscan`
* Depending on run_mode, Claude's final output will be a final localization or patch diff json report.

## Configuration
Batch experiment implementation pending usage state monitoring

Set the ARVO vulnerability ID via **`experiment_setup.json`** in the project root. Also set the following:

```json
{
    "arvo_id": 42538667,
    "agent": "claude",
    "is_loc_mode": true,
    "is_patch_mode": false,
    "loc_run_id": "",
    "is_resume": false,
    "resume_id": ""
}
```
* arvo_id - arvo vulnerability localId to run experiment on
* agent - only claude supported currently (will reimplement codex logic in updated framework)
* is_loc_mode - set to true to conduct localization run first (or alone)
* is_patch_mode - set to true to conduct patching run second (or alone)
* loc_run_id - patching run will source localization context from provided loc run_id. If missing or invalid, caro will try generating a new localization run.
* is_resume - if a previous run exceeded usage limit mark this true to attempt resuming that interrupted session
* resume_id - the session id of the run to continue. leave this empty to resume the most recent session

## To Conduct Experiment

After setting an **'arvo_id'** in the **'experiment_setup.json'** run caro.py

## Run Tables
### runs
* Each row represents a localization or patch experiment run.
* run_id - unique identifier of a run: arvo-{vulnerability ID#}-vul-{run timestamp}-{run mode}
* result - the coding agent's final message explaining the run result
* result_json - the dictionary containing either vulnerability localization context or patch diffs
* agent thought and insight logs - subset of agent messages intended to capture impactful decisions and summarize the run
* metrics - include duration, cost, and token usage by type and model
* session_id - unique identifier for the agent run which can be used to restart interrupted sessions
* command - documentation of the call to the coding agent
* agent_log - the coding agent's full trace
* caro_log - the experiment orchestration program's run log
* run_mode - loc: localization run to find the root cause of the vulnerability. patch: patching run to fix the root cause of the crash
* prompt - record of just the prompt portion of the coding agent command. The cited markdown files should also be considered part of the run's artifacts, but are static and thus not preserved in each db entry.

### run_events
Many entries per run store each discrete agent action by type and turn along with usage data dictionary
* event_num - chronological order of the events
* event_type - text: agent messages, thinking: agent's internal dialogue, tool_use: agent's command executions 
* event_usage - dictionary that stores discrete usage details for each turn

### patch_data
One entry per run stores patch data and logs whether it successfully resolved the crash
* experiment_tag - use tags to track experiment variations (ie baseline patch with no localization context)
* loc_source - the localization run id or other description of the context given to agent during this patch run
* is_crash_resolved - boolean tracks whether the generated patch successfully resolved the crash
* patch_crash_log - stores the resulting crash (or successful execution) when POC is re-ran after recompiling after patching

## caro crashes
If caro crashes with a Keyboard Interrupt message, check your system's storage utilization. Experiments using numerous arvo docker containers result in many dangling docker images taking up large amounts of space and will require regular pruning.