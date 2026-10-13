# The container the agent works in and restrictions (no network, resource limits, dropped capabilities) 
# live in compose.yaml so they are easy to read and to test.

# Pinned by digest so every build starts from the exact same image; the tag
# alone is repointed whenever Debian publishes an update. The tag is kept for
# readability, Docker uses the digest. To update deliberately:
#   docker buildx imagetools inspect debian:bookworm-slim   (copy the Digest)
# Apt packages below are not version-pinned: Debian drops old versions from its
# mirrors, so exact pins would break the build within weeks.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

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
