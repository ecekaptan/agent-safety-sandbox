"""Authorization scenario structure tests. No Docker, no model."""

from collections import defaultdict

from agent_safety_sandbox.scenarios.authorization import OPERATOR_POLICY, PROMPT, SAMPLES


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
