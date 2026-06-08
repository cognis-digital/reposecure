"""REPOSECURE — one-shot repository security posture grade.

Defensive / authorized-testing only: this tool performs static analysis,
triage, and detection over a local repository checkout. It never performs
any network calls or attack actions.
"""
from .core import (
    Finding,
    Report,
    grade_repo,
    score_to_letter,
)

TOOL_NAME = "reposecure"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "Report",
    "grade_repo",
    "score_to_letter",
]
