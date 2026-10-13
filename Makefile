.PHONY: setup build eval logs test lint attack attack-all

BASELINE := src/agent_safety_sandbox/baseline.py
COMPOSE := sandbox/compose.yaml

# Scenario files
PROMPT_INJECTION := src/agent_safety_sandbox/scenarios/prompt_injection.py
SECRET_EXFIL := src/agent_safety_sandbox/scenarios/secret_exfil.py
SCOPE_CREEP := src/agent_safety_sandbox/scenarios/scope_creep.py
SABOTAGE := src/agent_safety_sandbox/scenarios/sabotage.py

# Optional log to read: make logs LOG=logs/<file>.eval (default: newest in ./logs)
LOG ?=

# Which scenario to run: make attack SCENARIO=prompt_injection
SCENARIO ?= prompt_injection

# Optional per-run model override, bypassing INSPECT_EVAL_MODEL in .env:
#   make attack SCENARIO=sabotage MODEL=openrouter/meta-llama/llama-3.3-70b-instruct
# Needs the matching key in .env (e.g. OPENROUTER_API_KEY).
MODEL ?=
MODEL_FLAG := $(if $(MODEL),--model $(MODEL),)

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

# Run a single adversarial scenario.
#   make attack                           — runs prompt_injection (default)
#   make attack SCENARIO=secret_exfil     — runs secret exfiltration
#   make attack SCENARIO=scope_creep      — runs scope creep
#   make attack SCENARIO=sabotage         — runs sabotage / refusal
#   make attack SCENARIO=sabotage MODEL=openrouter/...  — override the model
attack:
	@test -f .env || { echo "No .env file. Run: make setup"; exit 1; }
	@test -n "$(MODEL)" || grep -Eq "^INSPECT_EVAL_MODEL=.+" .env || { echo "Set INSPECT_EVAL_MODEL in .env or pass MODEL="; exit 1; }
	uv run inspect eval src/agent_safety_sandbox/scenarios/$(SCENARIO).py $(MODEL_FLAG)

# Run all adversarial scenarios.
attack-all:
	@test -f .env || { echo "No .env file. Run: make setup"; exit 1; }
	@test -n "$(MODEL)" || grep -Eq "^INSPECT_EVAL_MODEL=.+" .env || { echo "Set INSPECT_EVAL_MODEL in .env or pass MODEL="; exit 1; }
	uv run inspect eval $(PROMPT_INJECTION) $(MODEL_FLAG)
	uv run inspect eval $(SECRET_EXFIL) $(MODEL_FLAG)
	uv run inspect eval $(SCOPE_CREEP) $(MODEL_FLAG)
	uv run inspect eval $(SABOTAGE) $(MODEL_FLAG)

# Print the tool-call timeline of an eval log.
logs:
	uv run python -m agent_safety_sandbox.logreader $(LOG)

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .
