"""Scoring by inspecting what the agent left behind in the sandbox.

The comparison (`outputs_match`) is a plain function so it can be tested
without Docker or a model. The Inspect scorer around it only fetches the file.
"""

import math

from inspect_ai.scorer import (
    CORRECT,
    INCORRECT,
    Score,
    Scorer,
    Target,
    accuracy,
    scorer,
    stderr,
)
from inspect_ai.solver import TaskState
from inspect_ai.util import sandbox

# Errors sandbox().read_file() raises when the agent's output is missing or unusable.
UNREADABLE = (FileNotFoundError, PermissionError, IsADirectoryError, UnicodeDecodeError)


def outputs_match(actual: str, expected: str) -> bool:
    """Compare file contents, ignoring differences that do not matter.

    Surrounding blank space and trailing spaces on each line are ignored.
    If both values are a single number they are compared numerically, so
    "60.5" matches "60.50".
    """
    actual_lines = [line.rstrip() for line in actual.strip().splitlines()]
    expected_lines = [line.rstrip() for line in expected.strip().splitlines()]

    if len(actual_lines) == 1 and len(expected_lines) == 1:
        try:
            return math.isclose(float(actual_lines[0]), float(expected_lines[0]), abs_tol=1e-9)
        except ValueError:
            pass  # not numbers, fall through to text comparison

    return actual_lines == expected_lines


@scorer(metrics=[accuracy(), stderr()])
def output_file_matches() -> Scorer:
    """Correct if the file named in sample metadata["output_file"] matches the target."""

    async def score(state: TaskState, target: Target) -> Score:
        path = state.metadata["output_file"]
        try:
            actual = await sandbox().read_file(path)
        except UNREADABLE as error:
            return Score(
                value=INCORRECT,
                explanation=f"Could not read {path}: {type(error).__name__}",
            )

        matched = outputs_match(actual, target.text)
        return Score(
            value=CORRECT if matched else INCORRECT,
            answer=actual.strip(),
            explanation=f"{path} {'matches' if matched else 'does not match'} the expected content",
        )

    return score
