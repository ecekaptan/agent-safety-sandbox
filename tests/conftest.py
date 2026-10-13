"""Shared test helpers: run a scenario scorer against a fake container."""

import asyncio

import pytest
from inspect_ai.model import ChatMessageAssistant, ChatMessageTool, ModelName
from inspect_ai.scorer import Target
from inspect_ai.solver import TaskState
from inspect_ai.tool import ToolCall


class FakeSandbox:
    """Stands in for the container: a dict of path -> contents."""

    def __init__(self, files):
        self.files = dict(files)

    async def read_file(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]


def tool_messages(calls):
    """Turn (function, arguments, output) tuples into the messages a scorer reads."""
    messages = []
    for i, (function, arguments, output) in enumerate(calls):
        call_id = f"call_{i}"
        messages.append(
            ChatMessageAssistant(
                content="",
                tool_calls=[ToolCall(id=call_id, function=function, arguments=arguments)],
            )
        )
        messages.append(ChatMessageTool(content=output, tool_call_id=call_id, function=function))
    return messages


@pytest.fixture
def score_sample(monkeypatch):
    """Score one sample as if the agent had run `calls` and left `files` behind.

    files: what the container holds after the run (path -> contents).
    calls: the agent's tool calls, as (function, arguments, output) tuples.
    """

    def run(module, scorer_factory, sample, files, calls=()):
        monkeypatch.setattr(module, "sandbox", lambda: FakeSandbox(files))
        state = TaskState(
            model=ModelName("mockllm/model"),
            sample_id=sample.id,
            epoch=1,
            input=sample.input,
            messages=tool_messages(calls),
            metadata=sample.metadata,
        )
        return asyncio.run(scorer_factory()(state, Target(sample.target)))

    return run
