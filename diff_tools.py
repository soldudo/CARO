import json
import logging
import subprocess
import sys
from arvo_tools import run_command, standby_container
from queries import get_vuln_id, get_result_json

logger = logging.getLogger(__name__)

def setup_logger():
    # logger for development debugging. This does not capture LLM info
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("diff-tools.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )

def run_and_report(cmd, label=None, **kwargs):
    """
    Run a command and log success/failure. Returns the
    CompletedProcess so callers can still inspect the result.
    """
    kwargs.setdefault("check", False)
    kwargs.setdefault("stdout", subprocess.PIPE)

    result = run_command(cmd, **kwargs)
    tag = label or cmd[0]

    if result.returncode != 0:
        logger.error(f'{tag} failed: {result.stderr}')
    else:
        if result.stdout:
            logger.info(f'{tag}: {result.stdout}')

    return result

def write_diff(patches: list[dict], output_path: str):
    """
    Concatenate the diff strings from each patch entry into a single
    unified diff file.  Each hunk is separated by a newline so tools
    like `git apply` and `patch` can parse them cleanly.
    """
    with open(output_path, "w", encoding="utf-8") as f:
        for i, patch in enumerate(patches):
            diff_text = patch["diff"]

            # Ensure each diff block ends with exactly one newline
            # before the next block starts
            if not diff_text.endswith("\n"):
                diff_text += "\n"

            f.write(diff_text)

            # Blank line between hunks for readability (not after the last one)
            if i < len(patches) - 1:
                f.write("\n")

patch_run_id = 'arvo-42531212-vul-1773871990-patch'
container_name = 'diff_test'
vuln_id = get_vuln_id(patch_run_id)[0]
patch_path = 'test.patch'
standby_container(container_name, vuln_id)
pwd = run_command(['pwd'], container_name=container_name, stdout=subprocess.PIPE).stdout.strip()

result_json = json.loads(get_result_json(patch_run_id)[0])
patches = result_json.get('patches', [])

write_diff(patches, 'test.patch')

patch_call = run_and_report(['git', 'apply', '--verbose', '-C1', pwd + '/' + patch_path], label='git apply', container_name=container_name)

arvo_compile_result = run_and_report(['arvo', 'compile'], label='arvo compile', container_name=container_name)

arvo_result = run_and_report(['arvo'], label='arvo', container_name=container_name)

print(arvo_result.stderr)