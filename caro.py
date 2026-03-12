import logging
import json
import os
import sys
from pathlib import Path
import time
from queries import get_context, update_caro_log, update_ground_truth
from agent_tools import conduct_run
from run_parser import parse_agent_run
from commit_files import download_commit_files

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(name)s] - %(message)s',
    handlers=[
        logging.FileHandler("caro.log", mode='w'), # recommend mode='w' otherwise multiple run logs will be stored for one run in db
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def load_config():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, 'experiment_setup.json')

    if not os.path.exists(config_path):
        logger.critical(f"Config file not found at {config_path}")
        print(f"CRITICAL: Config file not found at {config_path}")
        sys.exit(1)

    try:
        with open(config_path, 'r') as f:
            data = json.load(f)
            logger.info(f'loaded experiment parameters: {data}')
            return data
            
    except json.JSONDecodeError as e:
        logger.critical(f"JSON file is corrupt or invalid: {e}")
        print(f"CRITICAL: JSON file is corrupt or invalid.\nError details: {e}")
        sys.exit(1)

if __name__ == "__main__":
    patch_url = None
    logger.info('######### Starting CARO Experiment Run #########')
    experiment_params = load_config()
    vuln_id = experiment_params.get('arvo_id')
    container_name = experiment_params.get('container_name')
    agent = experiment_params.get('agent', 'codex')
    resume_flag = experiment_params.get('resume_flag', False) 
    resume_id = experiment_params.get('resume_id', None)

    
    # Definine the run name (previously container) as arvo-vuln_id-vuln_flag-timestamp
    run_id = f'arvo-{vuln_id}-vul{int(time.time())}'
    logger.info(f'Experiment assigned run_id: {run_id}')

    # Get project and crash type from ARVO.db
    project, crash_type, patch_url = get_context(vuln_id)
    logger.info(f"Experiment setup for ARVO ID {vuln_id}: project={project}, crash_type={crash_type}, patch_url={patch_url}")
    # Does not check for patch url which isn't critical to execution
    if project is None or crash_type is None: 
        context_error = f"ERROR: Missing context - project is {project} and crash_type is {crash_type} for ID {vuln_id}. Execution aborted."
        logger.error(context_error)
        raise ValueError(context_error)

    if not resume_flag:
        # localization only prompt
        prompt = f'Investigate the memory safety vulnerability causing the crash [{crash_type}] in the {project} project as shown in the opt/agent/crash.log file. Please initialize your environment using the opt/agent/memory_safety_agent.md persona. Use the patterns and checklist provided in the opt/agent/memory_safety_skills.md file. Localize the source causing this crash by providing the relevant files, functions and lines.'
    else:
        prompt = 'continue where you left off'
        resume_id = experiment_params.get('resume_id', None)

    run_params = {
        "vuln_id": vuln_id,
        "run_id": run_id,
        "container_name": container_name,
        "prompt": prompt,
        "agent": agent,
        "resume_flag": resume_flag,
        "resume_session_id": resume_id,
        "patch_url": patch_url
    }
 
    # conduct the experiment
    try:
        parse_agent_run(conduct_run(**run_params))
    except Exception as e:
        logger.error(f'Error encountered: {e}')

    # Ground truth logic deactivated pending rework to diff
    
    # copy original versions of modified files to db
    
    # run_path = Path(__file__).parent / 'runs' / run_id

    # # download ground truth from repo commit url
    # try:
    #     ground_truth_files = download_commit_files(patch_url, run_path)
    # except Exception as e:
    #     logger.error(f'Skipping download. Error getting commit files from {patch_url}: {e}') 
    #     ground_truth_files = []
    
    # # send ground truth files to db
    # for gt_file in ground_truth_files:
    #     gt_path = Path(gt_file)
    #     logger.debug(f'gt_path: {gt_path}')

    #     try:         
    #         relative_path = gt_path.relative_to(run_path)
    #         logger.info(f'relative_path_str: {relative_path}')

    #         # consider adding this check
    #         # if len(relative_path.parts) > 1 and relative_path.parts[0] == 'grndtrth':
                
    #         truncated_gt_path = Path(*relative_path.parts[1:])  # remove 'grndtrth' folder for db path
    #         logger.info(f'truncated_gt_path for db: {truncated_gt_path}')

    #         with open(gt_file, 'r', encoding='utf-8', errors='replace') as f:
    #             content = f.read()
    #     except ValueError:
    #         logger.error(f'Path error: GT file at {gt_path} is not inside {run_path}')

    #     except Exception as e:
    #         logger.error(f'Error reading ground truth file {gt_file} for database insertion: {e}')

    #     try:
    #         update_ground_truth(vuln_id=vuln_id, file_path=str(truncated_gt_path), content=content)
    #     except Exception as e:
    #         logger.error(f'Database error inserting ground truth for {truncated_gt_path}: {e}')

    logger.info('######### CARO Experiment Run Complete #########')
    caro_dir = Path(__file__).parent
    caro_log_path = caro_dir / 'caro.log'

    # update caro_log in db
    try:
        update_caro_log(run_id, str(caro_log_path))
    except Exception as e:
        logger.error(f'Error updating caro_log in database for run {run_id}: {e}')