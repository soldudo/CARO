import argparse
import logging
import json
import os
import sys
from pathlib import Path
import time
from queries import get_context, get_localization, update_caro_log
from agent_tools import conduct_run
from run_parser import parse_agent_run

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(name)s] - %(message)s',
    handlers=[
        logging.FileHandler("caro.log", mode='w'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def load_config(config_path=None):
    if config_path is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base_dir, 'experiment_setup.json')

    if not os.path.exists(config_path):
        logger.critical(f"Config file not found at {config_path}")
        sys.exit(1)

    try:
        with open(config_path, 'r') as f:
            data = json.load(f)
            logger.info(f'loaded experiment parameters: {data}')
            return data
    except json.JSONDecodeError as e:
        logger.critical(f"JSON file is corrupt or invalid: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default=None, help='Path to experiment config JSON')
    args = parser.parse_args()

    caro_dir = Path(__file__).parent
    caro_log_path = caro_dir / 'caro.log'

    logger.info('######### Starting CARO Experiment Run #########')
    experiment_params = load_config(args.config)

    vuln_id        = experiment_params.get('arvo_id')
    container_name = experiment_params.get('container_name', 'rootainer')
    agent          = experiment_params.get('agent', 'claude')
    is_loc_mode    = experiment_params.get('is_loc_mode', True)
    is_patch_mode  = experiment_params.get('is_patch_mode', False)
    loc_run_id     = experiment_params.get('loc_run_id', None)
    is_resume      = experiment_params.get('is_resume', False)
    resume_id      = experiment_params.get('resume_id', None)

    if not vuln_id or not isinstance(vuln_id, int):
        logger.critical(f'ERROR: Invalid arvo vulnerability id: {vuln_id}')
        sys.exit(1)

    # Patch-only mode requires loc_run_id or is_resume
    if is_patch_mode and not is_loc_mode and not loc_run_id and not is_resume:
        logger.critical('ERROR: patch-only mode requires loc_run_id to be set')
        sys.exit(1)

    # ── Refresh Claude credentials from rootainer ──────────────────────────────
    # OAuth tokens expire — copy fresh credentials before each run
    import tempfile as _tmpmod
    with _tmpmod.TemporaryDirectory() as _tmp:
        _creds = os.path.join(_tmp, '.credentials.json')
        _cfg   = os.path.join(_tmp, '.claude.json')
        import subprocess as _sp
        if _sp.run(['docker', 'cp', 'rootainer:/root/.claude/.credentials.json', _creds],
                   capture_output=True).returncode == 0:
            _sp.run(['docker', 'cp', _creds, f'{container_name}:/root/.claude/.credentials.json'],
                    capture_output=True)
        if _sp.run(['docker', 'cp', 'rootainer:/root/.claude.json', _cfg],
                   capture_output=True).returncode == 0:
            _sp.run(['docker', 'cp', _cfg, f'{container_name}:/root/.claude.json'],
                    capture_output=True)
        logger.info(f'Claude credentials refreshed from rootainer → {container_name}')

    run_id = f'arvo-{vuln_id}-vul-{int(time.time())}'
    logger.info(f'Experiment base run_id: {run_id}')

    project, crash_type, patch_url = get_context(vuln_id)
    logger.info(f"ARVO {vuln_id}: project={project}, crash_type={crash_type}")
    if project is None or crash_type is None:
        logger.error(f"Missing context for {vuln_id} — aborting")
        sys.exit(1)

    # ── Pre-fetch loc context if patch mode + existing loc_run_id supplied ─────
    # Allows patch-only mode and skipping a re-run when context already exists
    loc_context = None
    current_loc_run_id = loc_run_id  # may be pre-supplied

    if is_patch_mode and loc_run_id:
        db_loc_result = get_localization(loc_run_id)
        if db_loc_result is not None:
            if db_loc_result[1] != vuln_id:
                logger.error(
                    f'loc_run_id {loc_run_id} belongs to vuln {db_loc_result[1]}, '
                    f'not {vuln_id} — aborting'
                )
                sys.exit(1)
            try:
                loc_context = json.loads(db_loc_result[0]) if db_loc_result[0] else {}
            except (json.JSONDecodeError, TypeError):
                loc_context = {}
            for v in (loc_context or {}).get('vulnerabilities', []):
                v.pop('confidence_score', None)
            if not loc_context:
                logger.warning(f'Loc context for {loc_run_id} is empty')
        else:
            if not is_loc_mode:
                logger.error(f'No loc result found for {loc_run_id} and is_loc_mode=false — aborting')
                sys.exit(1)
            logger.warning(f'No loc result found for {loc_run_id} — will run localization first')

    # ── Localization run ───────────────────────────────────────────────────────
    if is_loc_mode:
        # Skip loc run if we already have valid context from a pre-supplied loc_run_id
        if loc_context is not None:
            logger.info(f'Skipping loc run — using pre-fetched context from {loc_run_id}')
        else:
            if not is_resume:
                loc_prompt = (
                    f'Investigate the memory safety vulnerability causing the crash [{crash_type}] '
                    f'in the {project} project as shown in the opt/agent/crash.log file. '
                    f'Please initialize your environment using the opt/agent/memory_safety_agent.md persona. '
                    f'Use the patterns and checklist provided in the opt/agent/memory_safety_skills.md file. '
                    f'Localize the source causing this crash by providing the relevant files, functions and lines. '
                    f'Finally, provide the full function call chain that leads to the crash site in the format: '
                    f'`func_a() [file.c:line] --> func_b() [file.c:line] --> ... --> crash_site() [file.c:line]`, '
                    f'tracing the execution path from the earliest entry point down to the exact line where '
                    f'the vulnerability is triggered.'
                )
                # Once resumed, subsequent patch run should not re-resume
                is_resume = False
            else:
                loc_prompt = 'continue where you left off'

            current_loc_run_id = run_id + '-loc'
            loc_run_params = {
                "vuln_id": vuln_id,
                "run_id": current_loc_run_id,
                "container_name": container_name,
                "prompt": loc_prompt,
                "agent": agent,
                "run_mode": "loc",
                "resume_flag": is_resume,
                "resume_session_id": resume_id,
                "patch_url": patch_url,
            }

            try:
                agent_rc = parse_agent_run(
                    conduct_run(**loc_run_params),
                    run_mode='loc'
                )
                logger.info('######### CARO Localization Run Complete #########')
                update_caro_log(run_id=current_loc_run_id, caro_log_path=str(caro_log_path))
                if agent_rc != 0:
                    logger.error(f'Localization agent exited with code {agent_rc}')
                    sys.exit(1)
            except Exception as e:
                logger.error(f'Localization run error: {e}')
                sys.exit(1)

    # ── Patch run ──────────────────────────────────────────────────────────────
    if is_patch_mode:
        if not is_resume:
            # If context wasn't pre-fetched (e.g. loc run just completed), fetch now
            if loc_context is None:
                db_loc_result = get_localization(current_loc_run_id) if current_loc_run_id else None
                if db_loc_result:
                    try:
                        loc_context = json.loads(db_loc_result[0]) if db_loc_result[0] else {}
                    except (json.JSONDecodeError, TypeError):
                        loc_context = {}
                    for v in (loc_context or {}).get('vulnerabilities', []):
                        v.pop('confidence_score', None)
                else:
                    logger.warning(f'No loc result found for {current_loc_run_id} — proceeding without context')
                    loc_context = {}

            if not loc_context:
                logger.warning('Localization context is empty — patch prompt will have no findings')

            patch_prompt = (
                f'Fix the root cause of the memory safety vulnerability causing the crash [{crash_type}] '
                f'in the {project} project. The crash log can be found at opt/agent/crash.log.\n\n'
                f'The following JSON contains localized vulnerability findings:\n\n'
                f'{json.dumps(loc_context, indent=2)}\n\n'
                f'For each entry in the vulnerabilities array:\n'
                f'1. Read the cited file and examine the specified lines\n'
                f'2. Apply a minimal fix addressing the root cause in the summary\n'
                f'3. If the summary references a correctly-handled parallel code path, mirror that approach\n\n'
                f'Produce a separate .diff per file. Do not combine fixes across different files.\n\n'
                f'Please initialize your environment using the opt/agent/patch_agent.md persona. '
                f'Use the patterns provided in the opt/agent/patch_skills.md file.'
            )
        else:
            patch_prompt = 'continue where you left off'

        patch_run_id = run_id + '-patch'
        patch_run_params = {
            "vuln_id": vuln_id,
            "run_id": patch_run_id,
            "container_name": container_name,
            "prompt": patch_prompt,
            "agent": agent,
            "run_mode": "patch",
            "loc_run_id": current_loc_run_id,
            "resume_flag": is_resume,
            "resume_session_id": resume_id,
            "patch_url": patch_url,
        }

        try:
            agent_rc = parse_agent_run(
                conduct_run(**patch_run_params),
                run_mode='patch',
                loc_run_id=current_loc_run_id
            )
            logger.info('######### CARO Patch Run Complete #########')
            update_caro_log(run_id=patch_run_id, caro_log_path=str(caro_log_path))
            if agent_rc != 0:
                logger.error(f'Patch agent exited with code {agent_rc}')
                sys.exit(1)
        except Exception as e:
            logger.error(f'Patch run error: {e}')
            sys.exit(1)

    logger.info('######### CARO Experiment Run Complete #########')
