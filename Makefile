.PHONY: setup build eval logs test lint

BASELINE := src/agent_safety_sandbox/baseline.py
COMPOSE := sandbox/compose.yaml

# Optional log to read: make logs LOG=logs/<file>.eval (default: newest in ./logs)
LOG ?=

# Install dependencies and create .env from the template if it is missing.
setup:
	uv sync
	@test -f .env || (cp .env.example .env && echo "Created .env. Add your model and API key to it.")

# Build the sandbox image the agent runs in.
build:
	docker compose -f $(COMPOSE) build

# Run the baseline task against the model named in .env.
eval:
	@test -f .env || { echo "No .env file. Run: make setup"; exit 1; }
	@grep -Eq "^INSPECT_EVAL_MODEL=.+" .env || { echo "Set INSPECT_EVAL_MODEL in .env"; exit 1; }
	uv run inspect eval $(BASELINE)

# Print the tool-call timeline of an eval log.
logs:
	uv run python -m agent_safety_sandbox.logreader $(LOG)

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .
