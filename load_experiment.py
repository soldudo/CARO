import json
from queries import insert_experiment

# discrete-loc-patch-pairs-fullmd config
# experiment_tag = 'discrete-loc-patch-pairs-fullmd'
# description = 'discrete loc patch pair runs with full v1.0 markdown pairs'
# prompt_json = {
#     'loc': 'Investigate the memory safety vulnerability causing the crash [{crash_type}] in the {project} project as shown in the opt/agent/crash.log file. Please initialize your environment using the opt/agent/memory_safety_agent.md persona. Use the patterns and checklist provided in the opt/agent/memory_safety_skills.md file. Localize the source causing this crash by providing the relevant files, functions and lines.',
#     'patch': '''Fix the root cause of the memory safety vulnerability causing the crash [{crash_type}] in the {project} project. The crash log can be found at opt/agent/crash.log.
#             The following JSON contains localized vulnerability findings.

#             {json.dumps(loc_context, indent=2)}
            
#             For each entry in the vulnerabilities array:
#             1. Read the cited file and examine the specified lines
#             2. Apply a minimal fix addressing the root cause in the summary
#             3. If the summary references a correctly-handled parallel code path, mirror that approach

#             Produce a separate .diff per file. Do not combine fixes across 
#             different files.

#             Please initialize your environment using the opt/agent/patch_agent.md persona. Use the patterns provided in the opt/agent/patch_skills.md file.
#             '''
# }
# markdown_files = ['memory_safety_skills.md', 'memory_safety_agent.md', 'patch_skills.md', 'patch_agent.md']

experiment_tag = 'baseline-patch-envmd'
description = 'baseline patch only run. markdowns only contain docker environment context'
prompt_json = {
    'patch': '''Fix the memory safety vulnerability causing the crash [{crash_type}] in the {project} project. The crash log can be found at opt/agent/crash.log.
            Produce a separate .diff per file. Do not combine fixes across 
            different files.

            Please initialize your environment using the opt/agent/patch_agent_env.md persona.
            '''
}
markdown_files = ['patch_agent_env.md']

prompt_template = json.dumps(prompt_json)

markdown_data = {}

for filename in markdown_files:
    # Use utf-8 encoding to prevent errors with special characters
    with open(filename, 'r', encoding='utf-8') as file:
        # Save the file content as the value, using the filename as the key
        markdown_data[filename] = file.read()

markdown_json = json.dumps(markdown_data)

insert_experiment(experiment_tag=experiment_tag, description=description, prompt_template=prompt_template, markdown_json=markdown_json)