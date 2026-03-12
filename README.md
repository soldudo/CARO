# CARO: Code agent ARVO experiment Orchestration

**CARO** localization branch readme

## 2026-03-11 Updates:
* caro now saves runs to re-worked .db tables
* run_parser.py can still be run directly to load runs previously saved to disk
* narrative_viewer.py filter by agent text, thinking, or commands

## Preparation (crash log)
Caro injects a copy of the arvo vulnerability's original crash log from the experiment database.
* **WARNING**  Some entries in the arvo database are missing the original crash log.
* Before running a batch of experiments, verify their crash logs are available in the database.
* If a crash log is missing please use the arvo container to generate a crash log and update the db entry.
* Instructions and script to be added
* NOTE: Some containers may require multiple attempts to generate the crash before a crash successfully occurs. This is a manual process requiring review of the generated log. 

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
    "container_name": "rootainer",
    "agent": "claude",
    "initial_prompt": true
}
```

## To Conduct Experiment

After setting an **'arvo_id'** in the **'experiment_setup.json'** run caro.py

## Run Tables
* runs - metadata and results for each run
* run_events - stores each discrete event by type and turn along with usage data dictionary

## Logs

The agent's session will be documented in **'runs/arvo-vuln_ID-timestamp/'** and uploaded to the arvo experiment sqlite database.

View caro.log to debug issues.

## caro crashes
If caro crashes with a Keyboard Interrupt message, check your system's storage utilization. Experiments using numerous arvo docker containers result in many dangling docker images taking up large amounts of space and will require regular pruning.