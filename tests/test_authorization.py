"""Authorization scenario structure tests. No Docker, no real model."""

from collections import defaultdict

import pytest
from inspect_ai import eval
from inspect_ai.model import ModelOutput, ModelUsage, get_model

from agent_safety_sandbox.scenarios.authorization import (
    OPERATOR_POLICY,
    PROMPT,
    SAMPLES,
    authorization,
)


def test_every_pair_has_one_comply_and_one_refuse():
    # The design depends on controls: a refusal only means something when the
    # same kind of action is done in the paired sample.
    pairs = defaultdict(list)
    for sample in SAMPLES:
        pairs[sample.metadata["pair"]].append(sample.metadata["expected"])
    for pair, expected in pairs.items():
        assert sorted(expected) == ["comply", "refuse"], pair


def test_operator_policy_is_in_the_system_prompt():
    assert OPERATOR_POLICY in PROMPT
    assert "records/" in OPERATOR_POLICY


def test_comply_samples_say_what_completion_means():
    for sample in SAMPLES:
        if sample.metadata["expected"] == "comply":
            assert sample.metadata.get("must_be_deleted") or sample.metadata.get("must_grow"), (
                sample.id
            )


def test_every_checked_file_is_put_in_the_workspace():
    for sample in SAMPLES:
        md = sample.metadata
        checked = (
            list(md.get("intact", {}))
            + list(md.get("preserved_lines", {}))
            + list(md.get("must_be_deleted", []))
            + list(md.get("must_grow", {}))
        )
        for path in checked:
            assert path in sample.files, f"{sample.id}: {path} is checked but never created"


def system_prompts_sent_to_model(tmp_path, **task_args):
    """Run the task with a mock model and return the system prompt of each sample."""
    prompts = {}

    def submit_at_once(input, tools, tool_choice, config):
        user_message = next(m.text for m in input if m.role == "user")
        prompts[user_message] = next(m.text for m in input if m.role == "system")
        output = ModelOutput.for_tool_call("mockllm/model", "submit", {"answer": "done"})
        # Without usage set, the mock model downloads a tokenizer to count tokens.
        output.usage = ModelUsage(input_tokens=1, output_tokens=1, total_tokens=2)
        return output

    logs = eval(
        authorization(**task_args),
        model=get_model("mockllm/model", custom_outputs=submit_at_once),
        sandbox="local",
        epochs=1,
        log_dir=str(tmp_path),
        display="none",
    )
    assert logs[0].status == "success"
    return prompts


@pytest.mark.parametrize(
    ("task_args", "sample_count", "rule_shown"),
    [({}, 4, True), ({"operator_policy": False}, 2, False)],
)
def test_operator_policy_switch_controls_what_the_model_sees(
    tmp_path, task_args, sample_count, rule_shown
):
    prompts = system_prompts_sent_to_model(tmp_path, **task_args)
    assert len(prompts) == sample_count
    for prompt in prompts.values():
        assert ("Operator policy" in prompt) is rule_shown
        assert ("audited" in prompt) is rule_shown


def test_removing_the_policy_keeps_the_audit_log_requests_unchanged():
    # Only the system prompt may differ, or the two runs cannot be compared.
    with_rule = {s.id: s.input for s in authorization().dataset}
    without_rule = {s.id: s.input for s in authorization(operator_policy=False).dataset}
    assert set(without_rule) == {"append_log_note", "hide_log_entry"}
    for sample_id, request in without_rule.items():
        assert request == with_rule[sample_id]
