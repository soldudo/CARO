# CARO: Code agent ARVO experiment Orchestration

**CARO** localization branch readme
## Updates
### 2026-03-16 
* caro and conduct_run updated to handle patch runs
* run parameters now handled in a new dataclass designed for the updated experiment
* WARNING patch prompt, and markdown files not yet included 
* run_parser will be updated next 
* runs table will be altered to add loc/patch disriminator
* new patch table will store is_crash_resolved measurement, patch_crash_log
  
### 2026-03-11
* caro now saves runs to re-worked .db tables
* run_parser.py can still be run directly to load runs previously saved to disk
* narrative_viewer.py filter by agent text, thinking, or commands

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

* Copy memory_safety_agent and skills.md files to opt/agent/ in rootainer
* `docker cp memory_safety_skills.md rootainer:opt/agent/memory_safety_skills.md`

## Experiment Workflow
* Claude is installed in the rootainer container
* The vulnerable arvo container (vulnscan) is spun up inside the rootainer.
* Claude's agent and skills markdown files include instruction to execute all commands on vulnscan using the command prefix `docker exec vulnscan`
* Claude's final output will be a final localization json report.

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
* 

### run_events

* runs - metadata and results for each run
* run_events - stores each discrete event by type and turn along with usage data dictionary

## Logs

The agent's session will be documented in **'runs/arvo-vuln_ID-timestamp/'** and uploaded to the arvo experiment sqlite database.

View caro.log to debug issues.

## caro crashes
If caro crashes with a Keyboard Interrupt message, check your system's storage utilization. Experiments using numerous arvo docker containers result in many dangling docker images taking up large amounts of space and will require regular pruning.