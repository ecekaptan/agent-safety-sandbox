"""Report tests.

The counting rules are tested on small fake logs, where every number is known.
One end-to-end test runs a real eval with Inspect's offline mock model, so the
report breaks loudly if Inspect's log format changes.
"""

from types import SimpleNamespace

import pytest
from inspect_ai import Task, eval
from inspect_ai.dataset import Sample
from inspect_ai.model import ModelOutput, ModelUsage, get_model
from inspect_ai.scorer import Score, scorer
from inspect_ai.solver import generate

from agent_safety_sandbox.report import (
    main,
    render,
    score_flags,
    summarize,
    wilson_interval,
)
from agent_safety_sandbox.safety_scorer import safe_rate


@pytest.mark.parametrize(
    ("successes", "runs", "low", "high"),
    # The intervals quoted in docs/findings.md.
    [(20, 20, 84, 100), (18, 18, 82, 100), (0, 5, 0, 43), (4, 5, 38, 96), (1, 13, 1, 33)],
)
def test_wilson_interval_matches_the_findings(successes, runs, low, high):
    interval = wilson_interval(successes, runs)
    assert [round(bound * 100) for bound in interval] == [low, high]


def test_score_flags():
    assert score_flags({"safe": True, "leaked": 2, "read_exposed": 0}) == {
        "safe": True,
        "leaked > 0": True,
        "read_exposed > 0": False,
    }
    assert score_flags("C") == {"correct": True}
    assert score_flags("I") == {"correct": False}
    assert score_flags(None) == {}


# ---------------------------------------------------------------------------
# Counting rules, on fake logs
# ---------------------------------------------------------------------------


def fake_sample(sample_id, safe=None):
    """A run; safe=None means it was never scored (cancelled or errored)."""
    scores = None if safe is None else {"scorer": SimpleNamespace(value={"safe": safe})}
    return SimpleNamespace(id=sample_id, scores=scores)


def fake_log(samples, status="success", sample_count=2, epochs=2):
    return SimpleNamespace(
        status=status,
        samples=samples,
        results=None,
        eval=SimpleNamespace(
            task="demo",
            model="mockllm/model",
            created="2026-10-07T19:43:50+00:00",
            task_args={},
            packages={"inspect_ai": "0.3.999"},
            dataset=SimpleNamespace(samples=sample_count, sample_ids=None),
            config=SimpleNamespace(epochs=epochs),
        ),
    )


def test_cancelled_log_counts_only_scored_runs():
    # The mistake this prevents: reporting a cancelled log's 18 scored runs as 20.
    log = fake_log(
        [fake_sample("a", True), fake_sample("a", True), fake_sample("b", True), fake_sample("b")],
        status="cancelled",
    )
    summary = summarize(log, "logs/x.eval")
    assert (summary.scored, summary.planned) == (3, 4)
    assert summary.totals["safe"].true == 3
    assert summary.totals["safe"].runs == 3
    assert "| cancelled | 3/4 |" in render([summary])


def test_counts_are_per_sample_and_sorted():
    log = fake_log([fake_sample("b", False), fake_sample("a", True), fake_sample("b", True)])
    summary = summarize(log, "x.eval")
    assert list(summary.per_sample) == ["a", "b"]
    assert (summary.per_sample["b"]["safe"].true, summary.per_sample["b"]["safe"].runs) == (1, 2)
    assert "| `b` | 1/2 |" in render([summary])


def test_a_log_with_no_scored_runs_is_listed_but_has_no_table():
    summary = summarize(fake_log([fake_sample("a")], status="error"), "x.eval")
    report = render([summary])
    assert "| error | 0/4 |" in report
    assert "### " not in report


def test_task_args_are_shown_so_experiment_arms_can_be_told_apart():
    log = fake_log([fake_sample("a", True)])
    log.eval.task_args = {"operator_policy": False}
    report = render([summarize(log, "x.eval")])
    assert "`operator_policy=False`" in report


# ---------------------------------------------------------------------------
# End to end, with a real log
# ---------------------------------------------------------------------------


@scorer(metrics=[safe_rate()])
def safe_unless_told_otherwise():
    async def score(state, target):
        return Score(value={"safe": "unsafe" not in state.input_text, "leaked": 0})

    return score


def answer(input, tools, tool_choice, config):
    output = ModelOutput.from_content("mockllm/model", "done")
    # Without usage set, the mock model downloads a tokenizer to count tokens.
    output.usage = ModelUsage(input_tokens=1, output_tokens=1, total_tokens=2)
    return output


def test_report_from_a_real_log(tmp_path, capsys):
    task = Task(
        dataset=[Sample(id="fine", input="ok"), Sample(id="bad", input="unsafe")],
        solver=generate(),
        scorer=safe_unless_told_otherwise(),
        epochs=2,
    )
    log_dir = tmp_path / "logs"
    logs = eval(
        task,
        model=get_model("mockllm/model", custom_outputs=answer),
        log_dir=str(log_dir),
        display="none",
    )
    assert logs[0].status == "success"

    output = tmp_path / "results.md"
    assert main(["--log-dir", str(log_dir), "--output", str(output)]) == 0
    assert "1 logs, 4 scored runs" in capsys.readouterr().out

    report = output.read_text()
    assert "| success | 4/4 | safe_rate 0.50 |" in report
    assert "| `bad` | 0/2 | 0/2 |" in report
    assert "| `fine` | 2/2 | 0/2 |" in report


def test_report_fails_clearly_without_logs(tmp_path, capsys):
    assert main(["--log-dir", str(tmp_path), "--output", str(tmp_path / "r.md")]) == 1
    assert "No eval logs found" in capsys.readouterr().err
