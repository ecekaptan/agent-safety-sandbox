"""Print a timeline of every tool call in an Inspect eval log.

    python -m agent_safety_sandbox.logreader             # newest log in ./logs
    python -m agent_safety_sandbox.logreader path/to/log.eval

This is the seed of the later monitor. Reading and printing are separate on
purpose: `extract_tool_calls` returns plain `ToolCall` records, so a monitor
can reuse it and replace the printing with checks.
"""

import argparse
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from inspect_ai.event import ToolEvent
from inspect_ai.log import EvalLog, list_eval_logs, read_eval_log

DEFAULT_LOG_DIR = "./logs"
DEFAULT_MAX_OUTPUT = 2000


@dataclass
class ToolCall:
    """One tool call made by the agent."""

    sample_id: str | int
    epoch: int
    timestamp: datetime
    function: str
    arguments: dict[str, Any]
    output: str
    error: str | None  # set when the tool call failed
    duration: float | None  # seconds, if the log recorded it


def result_as_text(result: Any) -> str:
    """Tool results are usually strings but can be numbers or content blocks."""
    if isinstance(result, str):
        return result
    if isinstance(result, list):
        return "\n".join(getattr(item, "text", f"[{type(item).__name__}]") for item in result)
    return getattr(result, "text", str(result))


def extract_tool_calls(log: EvalLog) -> list[ToolCall]:
    """Every tool call in the log, grouped by sample and ordered by time."""
    calls = []
    for sample in log.samples or []:
        events = [event for event in sample.events if isinstance(event, ToolEvent)]
        for event in sorted(events, key=lambda event: event.timestamp):
            calls.append(
                ToolCall(
                    sample_id=sample.id,
                    epoch=sample.epoch,
                    timestamp=event.timestamp,
                    function=event.function,
                    arguments=dict(event.arguments),
                    output=result_as_text(event.result),
                    error=f"{event.error.type}: {event.error.message}" if event.error else None,
                    duration=event.working_time,
                )
            )
    return calls


def read_tool_calls(log_file: str) -> list[ToolCall]:
    """Read a log file from disk and return its tool calls."""
    # Large values in events are stored once as attachments. Resolve them so
    # we get the real arguments and output instead of references.
    return extract_tool_calls(read_eval_log(log_file, resolve_attachments=True))


def latest_log_file(log_dir: str = DEFAULT_LOG_DIR) -> str:
    """Path of the newest eval log in log_dir."""
    logs = list_eval_logs(log_dir)  # newest first
    if not logs:
        raise FileNotFoundError(f"No eval logs found in {log_dir}. Run `make eval` first.")
    return logs[0].name


def indent(text: str, spaces: int) -> str:
    return "\n".join(" " * spaces + line for line in text.splitlines())


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [{len(text) - limit} more characters]"


def format_tool_call(call: ToolCall, max_output: int = DEFAULT_MAX_OUTPUT) -> str:
    time = call.timestamp.astimezone(UTC).isoformat(timespec="milliseconds")
    duration = f"  ({call.duration:.2f}s)" if call.duration is not None else ""
    lines = [f"{time}  {call.function}{duration}"]
    for name, value in call.arguments.items():
        lines.append(f"  {name}:")
        lines.append(indent(str(value), 4))
    lines.append("  output:")
    lines.append(indent(truncate(call.output, max_output), 4) or "    (empty)")
    if call.error:
        lines.append("  error:")
        lines.append(indent(call.error, 4))
    return "\n".join(lines)


def format_timeline(calls: list[ToolCall], max_output: int = DEFAULT_MAX_OUTPUT) -> str:
    if not calls:
        return "No tool calls in this log."
    blocks = []
    current_sample = None
    for call in calls:
        sample = (call.sample_id, call.epoch)
        if sample != current_sample:
            blocks.append(f"=== sample {call.sample_id} (epoch {call.epoch}) ===")
            current_sample = sample
        blocks.append(format_tool_call(call, max_output))
    return "\n\n".join(blocks)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print the tool-call timeline of an eval log.")
    parser.add_argument("log_file", nargs="?", help="Log to read (default: newest in --log-dir).")
    parser.add_argument("--log-dir", default=DEFAULT_LOG_DIR)
    parser.add_argument(
        "--max-output",
        type=int,
        default=DEFAULT_MAX_OUTPUT,
        help="Characters of each tool output to show.",
    )
    args = parser.parse_args(argv)

    try:
        log_file = args.log_file or latest_log_file(args.log_dir)
    except FileNotFoundError as error:
        print(error, file=sys.stderr)
        return 1

    calls = read_tool_calls(log_file)
    print(f"Log: {log_file}")
    print(f"Tool calls: {len(calls)}\n")
    print(format_timeline(calls, args.max_output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
