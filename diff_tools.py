import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
from arvo_tools import run_command, standby_container, cleanup_container, docker_copy
from queries import get_vuln_id, get_result_json, get_context, get_original_crash_log, update_patch_crash_results

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
    kwargs.setdefault("stderr", subprocess.PIPE)

    result = run_command(cmd, **kwargs)
    tag = label or cmd[0]

    logger.info(f'{tag} (rc={result.returncode})')
    if result.stderr:
        logger.debug(f'{tag} stderr: {result.stderr}')
    if result.stdout:
        logger.debug(f'{tag} stdout: {result.stdout}')

    return result

def write_diff(patches: list[dict], output_path: str):
    """
    Concatenate the diff strings from each patch entry into a single
    unified diff file.  Each hunk is separated by a newline so tools
    like `git apply` and `patch` can parse them cleanly.
    """
    with open(output_path, "w", encoding="utf-8") as f:
        for i, patch in enumerate(patches):
            diff_text = patch.get('diff', '')
            logger.debug(f'Loading diff: {diff_text}')
            # Ensure each diff block ends with exactly one newline
            # before the next block starts
            if not diff_text.endswith("\n"):
                diff_text += "\n"

            f.write(diff_text)

def handle_fuzzer_result(arvo_result, container_name):
    fuzzer_output = (arvo_result.stdout or '') + (arvo_result.stderr or '')
    rc = arvo_result.returncode

    logger.info(f'Fuzzer exit code: {rc}')
    logger.info(f'Fuzzer output:\n{fuzzer_output}')

    is_crash_resolved = None

    while True:
        print('\n--- Fuzzer Output ---')
        print(fuzzer_output)
        print(f'Exit code: {rc}')
        print('---------------------')
        choice = input('[r]e-run  |  [c]lassify  |  [q]uit: ').strip().lower()

        if choice == 'r':
            arvo_result = run_and_report(['arvo'], label='arvo', container_name=container_name)
            fuzzer_output = (arvo_result.stdout or '') + (arvo_result.stderr or '')
            rc = arvo_result.returncode

        elif choice == 'c':
            # Sub-menu for classification
            class_choice = input('Classify result: [s]uccess (Patch fixed vulnerability) | [u]nsuccessful (Crash persists) | [b]ack: ').strip().lower()
            
            if class_choice == 's':
                is_crash_resolved = True
                logger.info('User indicated fuzzer_output shows crash RESOLVED')
                break  # Exits the loop and continues the script
            elif class_choice == 'u':
                is_crash_resolved = False
                logger.info('User indicated fuzzer_output shows patch UNSUCCESSFUL')
                break  # Exits the loop and continues the script
            elif class_choice == 'b':
                continue # Returns to the main [r|s|c|q] menu
            else:
                print('Invalid choice. Returning to main menu.')

        elif choice == 'q':
            break
        else:
            print('Invalid choice.')

    return is_crash_resolved, fuzzer_output

def main():
    logging.basicConfig(
        filename='diff_tools.log', 
        level=logging.INFO,             
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description="Script to execute patch and test workflow.")
    
    parser.add_argument(
        '--patch-run-id', 
        type=str,           # Change to int if the ID is strictly numerical
        required=True,      # Forces the user to provide this when running the script
        help="Unique identifier for the specific patch run to write and test."
    )
    
    args = parser.parse_args()
    patch_run_id = args.patch_run_id
    
    logger.info(f"Starting patch write & test for Patch Run ID: {patch_run_id}")

    container_name = patch_run_id
    vuln_id = get_vuln_id(patch_run_id)[0]

    project, crash_type, _ = get_context(vuln_id)
    original_fuzzer_output = get_original_crash_log(vuln_id)
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_patch_path = os.path.join(temp_dir, "agent_combined.patch")

            standby_container(container_name, vuln_id)
            pwd = run_command(['pwd'], container_name=container_name, stdout=subprocess.PIPE).stdout.strip()
            logger.info(f'arvo container working directory: {pwd}')

            # git_apply_cmd = ['git', 'apply', '--verbose', '-p0', '-C1']
            
            # if pwd == '/src':
            #     patch_cmd
            #     git_apply_cmd.extend(['--directory', project])

            # git_apply_cmd.append(pwd + '/' + 'agent_combined.patch')

            # running arvo to generate original crash report can cause compilation errors affecting validity of POC re-test
            # original_arvo_result = run_and_report(['arvo'], label='arvo', container_name=container_name)
            # original_fuzzer_output = (original_arvo_result.stderr or '')


            logger.info(f'Original arvo fuzzer output:\n {original_fuzzer_output}')

            # get the result_json of the provided patch run
            result_json = json.loads(get_result_json(patch_run_id)[0])
            patches = result_json.get('patches', [])

            write_diff(patches, temp_patch_path)

                                            #  , '<', ])pwd + '/' + 'agent_combined.patch')
            # docker_copy(container_name=container_name, src_path=temp_patch_path, dest_path=pwd + '/' + 'agent_combined.patch', container_source_flag=False)
            with open(temp_patch_path, "r", encoding="utf-8") as f:
                diff_string = f.read()
            # stay in with block to access diff
            patch_cmd = ['patch']
            if pwd == '/src':
                patch_cmd
                patch_cmd.extend(['--directory', project])
            
            gnu_patch_cmd = patch_cmd + ['-p0', '--force', '--no-backup-if-mismatch', '--ignore-whitespace']

            patch_result = run_and_report(gnu_patch_cmd, label='patch (p0)', container_name=container_name, input=diff_string)

            if patch_result.returncode != 0:
                logger.info(f'gnu style patch failed (rc:{patch_result.returncode}): {(patch_result.stdout or '') + (patch_result.stderr or '')}')
                logger.info('attempting git style patch..')
                git_patch_cmd = patch_cmd + ['-p1', '--force', '--no-backup-if-mismatch', '--ignore-whitespace']
                patch_result = run_and_report(git_patch_cmd, label='patch (p1)', container_name=container_name, input=diff_string)

        if patch_result.returncode != 0:
            logger.error(f'Patch failed to apply (rc:{patch_result.returncode}), aborting.')
            logger.info(f'patch output: {(patch_result.stdout or '') + (patch_result.stderr or '')}')
            print('\n--- Patch Failed ---')
            print(patch_result.stderr or 'No error output captured.')
            print('--------------------')
            input('Press Enter to exit...')
            sys.exit(1)

        arvo_compile_result = run_and_report(['arvo', 'compile'], label='arvo compile', container_name=container_name)
        compile_errors = arvo_compile_result.stderr
        logger.info(f'Examine compile stderr to validate fuzz test integrity \n{compile_errors}')

        patch_arvo_result = run_and_report(['arvo'], label='arvo', container_name=container_name)
        print('\n--- Original Fuzzer Output ---')
        print(original_fuzzer_output)
        print('---------------------')

        is_crash_resolved, patch_crash_log = handle_fuzzer_result(patch_arvo_result, container_name)

        if is_crash_resolved is not None:
            update_patch_crash_results(run_id=patch_run_id, is_crash_resolved=is_crash_resolved, patch_crash_log=patch_crash_log, compile_errors=compile_errors)

    except Exception as e:
        logger.error(f'Error: {e}')

    finally:
        cleanup_container(patch_run_id)

if __name__ == "__main__":
    main()