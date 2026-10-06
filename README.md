# agent-safety-sandbox

A test environment for measuring how safely an AI agent behaves when it has
real tools.

An agent is given tasks inside an isolated Docker container, with bash and
Python tools, and everything it does is logged. The project is built on
[Inspect](https://inspect.aisi.org.uk), the UK AI Security Institute's
evaluation framework.

**Status: phase 1.** There is one benign baseline task and a log reader.
Attack scenarios, a network egress proxy and a policy layer come later
(see [Roadmap](#roadmap)).

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (it installs Python 3.11+ for you if needed)
- Docker Engine 24.0.6 or later with Docker Compose 2.21.0 or later
  (Inspect checks these versions)
- GNU Make
- An API key for a model provider. The project installs the Anthropic SDK;
  to use another provider, add its package with `uv add` and set its key
  in `.env`.

## Run the baseline

```bash
make setup    # install dependencies, create .env from .env.example
```

Open `.env` and set `INSPECT_EVAL_MODEL` (for example
`anthropic/<model-name>`) and the provider's API key. `.env` is git-ignored;
keep keys out of everything else.

```bash
make build    # build the sandbox image
make eval     # run the three baseline samples against the model in .env
make logs     # print the tool-call timeline of the newest run
```

`make eval` writes a log to `./logs`. To read a specific log, use
`make logs LOG=logs/<file>.eval`. For Inspect's interactive viewer, run
`uv run inspect view`.

Development:

```bash
make test     # unit tests: no model, API key, network or Docker needed
make lint     # ruff check and format check
```

## What the baseline does

`src/agent_safety_sandbox/baseline.py` defines three samples. For each one,
Inspect starts a fresh container, copies an input file into the working
directory, and lets a ReAct agent use `bash` and `python` until it submits.

| Sample | Input | Expected output file |
| --- | --- | --- |
| `csv_total` | `orders.csv` | `result.txt` with the sum of a column |
| `log_error_count` | `app.log` | `error_count.txt` with the number of ERROR lines |
| `json_enabled_features` | `features.json` | `enabled.txt` with sorted names |

The scorer reads the output file back out of the container and compares it
with the expected content. It does not trust what the agent says it did.

## The sandbox

Defined in `sandbox/Dockerfile` and `sandbox/compose.yaml`:

- runs as a non-root user (uid 1000)
- no network (`network_mode: none`)
- no host directories mounted, no Docker socket
- not privileged, all Linux capabilities dropped, `no-new-privileges`
- limits: 1 CPU, 512 MB memory, 256 processes

`tests/test_sandbox_config.py` fails if one of these settings is removed.

Two limits worth knowing:

- These settings restrict the container only. The eval process itself runs
  on your machine and talks to the model provider over the network.
- A container shares the host kernel. It is a reasonable boundary for benign
  tasks, not a strong one against a determined escape attempt.

## Layout

```
sandbox/                        Dockerfile and compose.yaml for the agent's container
src/agent_safety_sandbox/
  baseline.py                   the baseline Inspect task and its samples
  scorers.py                    scorer that checks files inside the container
  logreader.py                  tool-call timeline (seed of the later monitor)
tests/                          unit tests
```

## Threat model

_Placeholder: to be written before the attack scenarios are added._

Questions it should answer:

- What is being protected (host, credentials, network, other containers)?
- Who is the adversary: a misaligned agent, a malicious task input
  (prompt injection), or both?
- Which behaviours count as unsafe, and how is each one detected?
- What is explicitly out of scope?

## Roadmap

Not built yet:

- attack scenarios: prompt injection, planted fake secrets, deliberate
  misconfigurations
- network egress proxy
- policy layer and monitor
- stronger isolation (gVisor), system-call monitoring
- CI

## License

MIT. See [LICENSE](LICENSE).
