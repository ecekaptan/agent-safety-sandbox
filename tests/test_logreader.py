"""Log reader tests.

Rather than hand-building log objects, these run a tiny eval with Inspect's
offline mock model and read the log it writes, so they break if Inspect's log
format changes.
"""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from inspect_ai import Task, eval
from inspect_ai.dataset import Sample
from inspect_ai.log import read_eval_log
from inspect_ai.model import (
    ChatMessageAssistant,
    ContentReasoning,
    ContentText,
    ModelOutput,
    ModelUsage,
    get_model,
)
from inspect_ai.solver import generate, use_tools
from inspect_ai.tool import ToolError, tool

from agent_safety_sandbox.logreader import (
    ToolCall,
    extract_reasoning,
    extract_tool_calls,
    format_reasoning,
    format_timeline,
    latest_log_file,
    main,
    read_tool_calls,
)


@tool
def add():
    async def execute(x: int, y: int):
        """Add two numbers.

        Args:
            x: First number.
            y: Second number.
        """
        return x + y

    return execute


@tool
def always_fails():
    async def execute(reason: str):
        """Fail on purpose.

        Args:
            reason: Why to fail.
        """
        raise ToolError(f"failed: {reason}")

    return execute


def scripted_model(input, tools, tool_choice, config):
    """Mock model: one tool call per sample, then a final answer."""
    if input[-1].role == "tool":
        output = ModelOutput.from_content("mockllm/model", "done")
    elif "fail" in input[-1].text:
        output = ModelOutput.for_tool_call("mockllm/model", "always_fails", {"reason": "testing"})
    else:
        output = ModelOutput.for_tool_call("mockllm/model", "add", {"x": 2, "y": 3})
    # Without usage set, the mock model downloads a tokenizer to count tokens.
    output.usage = ModelUsage(input_tokens=1, output_tokens=1, total_tokens=2)
    return output


@pytest.fixture(scope="module")
def log_dir(tmp_path_factory):
    """A directory holding one real eval log with two samples."""
    directory = tmp_path_factory.mktemp("logs")
    task = Task(
        dataset=[
            Sample(id="adds", input="Please add 2 and 3."),
            Sample(id="fails", input="Please fail."),
        ],
        solver=[use_tools([add(), always_fails()]), generate()],
    )
    logs = eval(
        task,
        model=get_model("mockllm/model", custom_outputs=scripted_model),
        log_dir=str(directory),
        display="none",
    )
    assert logs[0].status == "success"
    return str(directory)


@pytest.fixture(scope="module")
def calls(log_dir):
    return read_tool_calls(latest_log_file(log_dir))


def test_finds_every_tool_call(calls):
    assert [(call.sample_id, call.function) for call in calls] == [
        ("adds", "add"),
        ("fails", "always_fails"),
    ]


def test_records_arguments_output_and_timestamp(calls):
    call = calls[0]
    assert call.arguments == {"x": 2, "y": 3}
    assert call.output == "5"
    assert call.error is None
    assert call.epoch == 1
    assert call.timestamp.tzinfo is not None
    assert call.duration is not None


def test_records_tool_errors(calls):
    call = calls[1]
    assert call.arguments == {"reason": "testing"}
    assert "failed: testing" in call.error


def test_extract_accepts_an_in_memory_log(log_dir):
    log = read_eval_log(latest_log_file(log_dir), resolve_attachments=True)
    assert len(extract_tool_calls(log)) == 2


def test_timeline_shows_what_happened(calls):
    timeline = format_timeline(calls)
    assert "=== sample adds (epoch 1) ===" in timeline
    assert "=== sample fails (epoch 1) ===" in timeline
    assert "add" in timeline
    assert "x:\n    2" in timeline
    assert "output:\n    5" in timeline
    assert "failed: testing" in timeline
    assert calls[0].timestamp.astimezone(UTC).isoformat(timespec="milliseconds") in timeline


def make_call(**overrides) -> ToolCall:
    fields = {
        "sample_id": "s1",
        "epoch": 1,
        "timestamp": datetime(2026, 1, 5, 9, 0, 0, tzinfo=UTC),
        "function": "bash",
        "arguments": {"command": "ls"},
        "output": "file.txt",
        "error": None,
        "duration": 0.5,
    }
    return ToolCall(**{**fields, **overrides})


def test_timeline_truncates_long_output():
    timeline = format_timeline([make_call(output="a" * 50)], max_output=10)
    assert "a" * 10 + "\n" in timeline
    assert "a" * 11 not in timeline
    assert "[40 more characters]" in timeline


def test_timeline_handles_empty_output_and_no_calls():
    assert "(empty)" in format_timeline([make_call(output="")])
    assert format_timeline([]) == "No tool calls in this log."


def test_timeline_orders_calls_within_a_sample():
    early = make_call(function="first")
    late = make_call(function="second", timestamp=datetime(2026, 1, 5, 9, 0, 5, tzinfo=UTC))
    timeline = format_timeline([early, late])
    assert timeline.index("first") < timeline.index("second")
    assert timeline.count("=== sample s1") == 1


def test_latest_log_file_fails_clearly_when_there_are_no_logs(tmp_path):
    with pytest.raises(FileNotFoundError, match="No eval logs found"):
        latest_log_file(str(tmp_path))


def test_cli_prints_timeline_for_newest_log(log_dir, capsys):
    assert main(["--log-dir", log_dir]) == 0
    printed = capsys.readouterr().out
    assert "Tool calls: 2" in printed
    assert "always_fails" in printed


def test_cli_accepts_an_explicit_log_file(log_dir, capsys):
    assert main([latest_log_file(log_dir)]) == 0
    assert "Tool calls: 2" in capsys.readouterr().out


def test_cli_reports_missing_logs(tmp_path, capsys):
    assert main(["--log-dir", str(tmp_path)]) == 1
    assert "No eval logs found" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Reasoning extraction
# ---------------------------------------------------------------------------


def fake_log_with_messages(*samples):
    return SimpleNamespace(samples=list(samples))


def test_extracts_reasoning_blocks_in_order():
    s1 = SimpleNamespace(
        id="s1",
        epoch=1,
        messages=[
            ChatMessageAssistant(
                content=[
                    ContentReasoning(reasoning="There is an injection; I will ignore it."),
                    ContentText(text="Done."),
                ]
            ),
            ChatMessageAssistant(content="plain string content, no reasoning"),
            ChatMessageAssistant(
                content=[ContentReasoning(reasoning="Second thought.")],
            ),
        ],
    )
    blocks = extract_reasoning(fake_log_with_messages(s1))
    assert [b.text for b in blocks] == [
        "There is an injection; I will ignore it.",
        "Second thought.",
    ]
    assert all(b.sample_id == "s1" and b.epoch == 1 for b in blocks)


def test_ignores_blank_reasoning():
    s = SimpleNamespace(
        id="s",
        epoch=1,
        messages=[ChatMessageAssistant(content=[ContentReasoning(reasoning="   ")])],
    )
    assert extract_reasoning(fake_log_with_messages(s)) == []


def test_no_reasoning_when_model_emits_none():
    s = SimpleNamespace(
        id="s",
        epoch=1,
        messages=[ChatMessageAssistant(content="just an answer")],
    )
    assert extract_reasoning(fake_log_with_messages(s)) == []


def test_format_reasoning_empty_is_explained():
    assert "No reasoning" in format_reasoning([])


def test_cli_reasoning_flag_runs(log_dir, capsys):
    # The mock-model log has no reasoning; the flag should still work.
    assert main(["--reasoning", "--log-dir", log_dir]) == 0
    out = capsys.readouterr().out
    assert "Reasoning blocks: 0" in out
    assert "No reasoning" in out
