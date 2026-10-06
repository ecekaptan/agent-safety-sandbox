# The container the agent works in. Keep it small and boring: the interesting
# restrictions (no network, resource limits, dropped capabilities) live in
# compose.yaml so they are easy to read and to test.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        curl \
        findutils \
        gawk \
        git \
        grep \
        jq \
        less \
        procps \
        python-is-python3 \
        python3 \
        sed \
        tar \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Non-root user with a fixed uid, and a working directory that it owns.
RUN useradd --create-home --uid 1000 --shell /bin/bash agent \
    && mkdir -p /home/agent/work \
    && chown agent:agent /home/agent/work

USER agent
WORKDIR /home/agent/work

# Inspect execs into a long-running container, so just keep it alive.
CMD ["tail", "-f", "/dev/null"]
