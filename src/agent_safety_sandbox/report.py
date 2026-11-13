"""Build docs/results.md from the eval logs, so no result is typed by hand.

    python -m agent_safety_sandbox.report                  # logs in ./logs
    python -m agent_safety_sandbox.report --log-dir path/  # e.g. downloaded logs

Every number in the report is counted from the logs. Two rules prevent the
mistakes that hand-copied numbers made:

- A run counts only if it was scored. A cancelled log can plan 20 runs and
  score 18; the report shows both, and rates use the 18.
- Each log is reported on its own. Logs scored under different rules are never
  added together, because the same key (say `safe`) meant different things.

The output contains no timestamps or paths of its own, so the same logs give
the same file wherever they are read from. Rebuilding it from downloaded logs
and finding no diff is the check that the published logs match.
"""

import argparse
import math
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from inspect_ai.log import EvalLog, list_eval_logs, read_eval_log

DEFAULT_LOG_DIR = "./logs"
DEFAULT_OUTPUT = "docs/results.md"


def wilson_interval(successes: int, runs: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a rate, as fractions.

    Unlike the plain "rate ± error" formula, it stays inside 0..1 and gives a
    sensible range for 0/5 or 20/20, which is where most of our results sit.
    """
    if runs == 0:
        return (0.0, 1.0)
    rate = successes / runs
    denominator = 1 + z**2 / runs
    centre = (rate + z**2 / (2 * runs)) / denominator
    half_width = z * math.sqrt(rate * (1 - rate) / runs + z**2 / (4 * runs**2)) / denominator
    return (max(0.0, centre - half_width), min(1.0, centre + half_width))


def score_flags(value: Any) -> dict[str, bool]:
    """Turn one run's score into yes/no flags that can be counted.

    Our scorers return dicts: booleans are kept as they are, and counts become
    "count > 0" (e.g. `leaked > 0` is a run that leaked anything). The
    baseline's "C"/"I" grade becomes `correct`.
    """
    if isinstance(value, dict):
        flags = {}
        for key, item in value.items():
            if isinstance(item, bool):
                flags[key] = item
            elif isinstance(item, int | float):
                flags[f"{key} > 0"] = item > 0
        return flags
    if isinstance(value, str):
        return {"correct": value == "C"}
    return {}


@dataclass
class Count:
    """How many scored runs had a flag set."""

    true: int = 0
    runs: int = 0

    def add(self, flag: bool) -> None:
        self.true += flag
        self.runs += 1


@dataclass
class LogSummary:
    """What one eval log says, counted from its samples."""

    file: str
    created: datetime
    task: str
    model: str
    task_args: dict[str, Any]
    status: str
    planned: int  # runs the eval set out to do (samples x epochs)
    scored: int  # runs that actually received a score
    metrics: dict[str, float]  # as Inspect recorded them at the end of the run
    inspect_version: str
    keys: list[str] = field(default_factory=list)  # flag names, in first-seen order
    per_sample: dict[str, dict[str, Count]] = field(default_factory=dict)
    totals: dict[str, Count] = field(default_factory=dict)


def planned_runs(log: EvalLog) -> int:
    dataset = log.eval.dataset
    samples = len(dataset.sample_ids) if dataset.sample_ids else (dataset.samples or 0)
    return samples * (log.eval.config.epochs or 1)


def summarize(log: EvalLog, file: str) -> LogSummary:
    metrics = {}
    for score in log.results.scores if log.results else []:
        for name, metric in score.metrics.items():
            metrics[name] = metric.value

    summary = LogSummary(
        file=Path(file).name,
        created=datetime.fromisoformat(log.eval.created).astimezone(UTC),
        task=log.eval.task,
        model=log.eval.model,
        task_args=dict(log.eval.task_args or {}),
        status=log.status,
        planned=planned_runs(log),
        scored=0,
        metrics=metrics,
        inspect_version=(log.eval.packages or {}).get("inspect_ai", "unknown"),
    )

    per_sample: dict[str, dict[str, Count]] = defaultdict(lambda: defaultdict(Count))
    totals: dict[str, Count] = defaultdict(Count)
    for sample in log.samples or []:
        if not sample.scores:
            continue  # cancelled or errored before scoring: not a run we can count
        summary.scored += 1
        # Each task has one scorer; take its score.
        score = next(iter(sample.scores.values()))
        for key, flag in score_flags(score.value).items():
            if key not in summary.keys:
                summary.keys.append(key)
            per_sample[str(sample.id)][key].add(flag)
            totals[key].add(flag)

    # Sorted, because Inspect stores samples in completion order, which varies.
    summary.per_sample = {sample: dict(per_sample[sample]) for sample in sorted(per_sample)}
    summary.totals = dict(totals)
    return summary


def load_summaries(log_dir: str) -> list[LogSummary]:
    """Every log in log_dir, oldest first."""
    summaries = [summarize(read_eval_log(info.name), info.name) for info in list_eval_logs(log_dir)]
    return sorted(summaries, key=lambda summary: summary.created)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def percent(fraction: float) -> str:
    return f"{round(fraction * 100)}%"


def format_count(count: Count | None, interval: bool = False) -> str:
    if count is None or count.runs == 0:
        return "n/a"
    text = f"{count.true}/{count.runs}"
    if interval:
        low, high = wilson_interval(count.true, count.runs)
        text += f" ({percent(low)}–{percent(high)})"
    return text


def format_args(task_args: dict[str, Any]) -> str:
    return ", ".join(f"`{key}={value}`" for key, value in task_args.items())


def format_metrics(metrics: dict[str, float]) -> str:
    return ", ".join(f"{name} {value:.2f}" for name, value in metrics.items()) or "none"


def label(summary: LogSummary) -> str:
    args = f" ({format_args(summary.task_args)})" if summary.task_args else ""
    return f"{summary.created:%Y-%m-%d %H:%M} · {summary.task}{args} · {summary.model}"


def render_index(summaries: list[LogSummary]) -> list[str]:
    lines = [
        "## Every log",
        "",
        "Scored runs out of planned runs. A log that planned more than it scored was",
        "cancelled or hit errors; only the scored runs count anywhere in this report.",
        "",
        "| Started (UTC) | Task | Model | Args | Status | Scored / planned"
        " | Metrics in log | inspect-ai | File |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for s in summaries:
        lines.append(
            f"| {s.created:%Y-%m-%d %H:%M} | {s.task} | {s.model} | {format_args(s.task_args)} "
            f"| {s.status} | {s.scored}/{s.planned} | {format_metrics(s.metrics)} "
            f"| {s.inspect_version} | `{s.file}` |"
        )
    return lines


def render_log(summary: LogSummary) -> list[str]:
    lines = [f"### {label(summary)}", "", f"`{summary.file}`", ""]
    lines.append("| Sample | " + " | ".join(f"`{key}`" for key in summary.keys) + " |")
    lines.append("| --- |" + " --- |" * len(summary.keys))
    for sample, counts in summary.per_sample.items():
        cells = [format_count(counts.get(key)) for key in summary.keys]
        lines.append(f"| `{sample}` | " + " | ".join(cells) + " |")
    totals = [format_count(summary.totals.get(key), interval=True) for key in summary.keys]
    lines.append("| **all** | " + " | ".join(totals) + " |")
    lines.append("")
    return lines


def render(summaries: list[LogSummary]) -> str:
    lines = [
        "# Results",
        "",
        "Generated by `make report` from the eval logs. Do not edit by hand: change",
        "the logs or the script, then regenerate. Interpretation, corrections and",
        "which runs matter are in [findings.md](findings.md).",
        "",
        f"Logs read: {len(summaries)}.",
        "",
        "Cells count runs where a flag was true, out of scored runs. Flags mean what",
        "the scorer meant on that date: `safe` in an October 7 log is not the same",
        "test as `safe` in an October 15 log. Totals show a 95% Wilson interval.",
        "",
    ]
    lines += render_index(summaries)
    lines += ["", "## Per-sample counts", "", "Logs with at least one scored run.", ""]
    for summary in summaries:
        if summary.scored:
            lines += render_log(summary)
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the results report from eval logs.")
    parser.add_argument("--log-dir", default=DEFAULT_LOG_DIR)
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Markdown file to write.")
    args = parser.parse_args(argv)

    summaries = load_summaries(args.log_dir)
    if not summaries:
        print(f"No eval logs found in {args.log_dir}.", file=sys.stderr)
        return 1

    Path(args.output).write_text(render(summaries))
    scored = sum(summary.scored for summary in summaries)
    print(f"Wrote {args.output}: {len(summaries)} logs, {scored} scored runs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
