from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

class RunMode(Enum):
    LOC = 'loc'
    PATCH = 'patch'
    TEST = 'test'

@dataclass
class RunParams:
    vuln_id: int
    run_id: str
    agent: str
    run_mode: str
    loc_run_id: str
    prompt: str
    is_resume: bool = False
    resume_session_id: Optional[str] = None


# Classes below are legacy from first implementation (codex patching runs)
class ContentType(Enum):
    ORIGINAL = "original"
    PATCHED = "patched"
    GROUND_TRUTH = "ground_truth"

class CrashLogType(Enum):
    ORIGINAL = "original"
    PATCH = "patch"

# dataclass object definitions

@dataclass
class LegacyRunRecord:
    run_id: str
    vuln_id: int

    workspace_relative: str
    patch_url: str
    prompt: str

    duration: float
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    total_tokens: int

    agent: str
    agent_model: str
    resume_flag: bool
    resume_id: str
    agent_log: str
    agent_reasoning: str
    modified_files: List[str] = field(default_factory=list)