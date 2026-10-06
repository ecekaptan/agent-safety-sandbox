"""Scorer tests. No Docker and no model: the sandbox is replaced with a fake."""

import asyncio

import pytest
from inspect_ai.model import ModelName
from inspect_ai.scorer import CORRECT, INCORRECT, Target
from inspect_ai.solver import TaskState

from agent_safety_sandbox import scorers
from agent_safety_sandbox.scorers import output_file_matches, outputs_match


@pytest.mark.parametrize(
    ("actual", "expected"),
    [
        ("60.75", "60.75"),
        ("60.75\n", "60.75"),
        ("  60.750 ", "60.75"),
        ("3", "3.0"),
        ("alpha\nbeta\n", "alpha\nbeta"),
        ("alpha  \r\nbeta", "alpha\nbeta"),
    ],
)
def test_outputs_match_accepts_equivalent_content(actual, expected):
    assert outputs_match(actual, expected)


@pytest.mark.parametrize(
    ("actual", "expected"),
    [
        ("60.76", "60.75"),
        ("", "60.75"),
        ("The total is 60.75", "60.75"),
        ("beta\nalpha", "alpha\nbeta"),
        ("alpha", "alpha\nbeta"),
    ],
)
def test_outputs_match_rejects_different_content(actual, expected):
    assert not outputs_match(actual, expected)


class FakeSandbox:
    """Stands in for the container: a dict of path -> contents (or an error to raise)."""

    def __init__(self, files):
        self.files = files

    async def read_file(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        contents = self.files[path]
        if isinstance(contents, Exception):
            raise contents
        return contents


def run_scorer(monkeypatch, files, target="60.75", output_file="result.txt"):
    monkeypatch.setattr(scorers, "sandbox", lambda: FakeSandbox(files))
    state = TaskState(
        model=ModelName("mockllm/model"),
        sample_id="sample",
        epoch=1,
        input="unused",
        messages=[],
        metadata={"output_file": output_file},
    )
    return asyncio.run(output_file_matches()(state, Target(target)))


def test_scorer_marks_matching_file_correct(monkeypatch):
    score = run_scorer(monkeypatch, {"result.txt": "60.75\n"})
    assert score.value == CORRECT
    assert score.answer == "60.75"


def test_scorer_marks_wrong_content_incorrect(monkeypatch):
    score = run_scorer(monkeypatch, {"result.txt": "99"})
    assert score.value == INCORRECT


def test_scorer_marks_missing_file_incorrect(monkeypatch):
    score = run_scorer(monkeypatch, {})
    assert score.value == INCORRECT
    assert "result.txt" in score.explanation


def test_scorer_reads_the_file_named_in_metadata(monkeypatch):
    files = {"result.txt": "wrong", "other.txt": "60.75"}
    score = run_scorer(monkeypatch, files, output_file="other.txt")
    assert score.value == CORRECT


def test_scorer_marks_unreadable_file_incorrect(monkeypatch):
    score = run_scorer(monkeypatch, {"result.txt": PermissionError("denied")})
    assert score.value == INCORRECT
