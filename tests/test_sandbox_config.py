"""Guard rails for the sandbox definition.

These tests only read the config files. They do not need Docker, and they do
not prove the container behaves as configured: they stop a restriction from
being removed by accident.
"""

from pathlib import Path

import yaml

SANDBOX_DIR = Path(__file__).resolve().parents[1] / "sandbox"


def load_services() -> dict:
    compose = yaml.safe_load((SANDBOX_DIR / "compose.yaml").read_text())
    return compose["services"]


def test_every_service_is_locked_down():
    for name, service in load_services().items():
        assert service.get("network_mode") == "none", f"{name}: network must be disabled"
        assert service.get("privileged", False) is False, f"{name}: must not be privileged"
        assert "volumes" not in service, f"{name}: no host directories or Docker socket"
        assert "ports" not in service, f"{name}: no published ports"
        assert "cap_add" not in service, f"{name}: no added capabilities"
        assert service.get("cap_drop") == ["ALL"], f"{name}: drop all capabilities"
        assert "no-new-privileges:true" in service.get("security_opt", [])


def test_every_service_has_resource_limits():
    for name, service in load_services().items():
        assert service.get("cpus"), f"{name}: needs a CPU limit"
        assert service.get("mem_limit"), f"{name}: needs a memory limit"
        assert service.get("pids_limit"), f"{name}: needs a process limit"


def test_every_service_runs_as_non_root():
    for name, service in load_services().items():
        user = str(service.get("user", ""))
        assert user and user.split(":")[0] not in ("0", "root"), f"{name}: must not run as root"


def test_no_top_level_volumes():
    compose = yaml.safe_load((SANDBOX_DIR / "compose.yaml").read_text())
    assert "volumes" not in compose


def test_dockerfile_switches_to_non_root_user():
    lines = (SANDBOX_DIR / "Dockerfile").read_text().splitlines()
    users = [line.split()[1] for line in lines if line.startswith("USER ")]
    assert users, "Dockerfile must set USER"
    assert users[-1] not in ("0", "root")


def test_base_image_is_pinned_by_digest():
    # A bare tag can be repointed upstream, silently changing the sandbox.
    lines = (SANDBOX_DIR / "Dockerfile").read_text().splitlines()
    bases = [line.split()[1] for line in lines if line.startswith("FROM ")]
    assert bases, "Dockerfile must have a FROM line"
    for base in bases:
        assert "@sha256:" in base, f"base image {base!r} must be pinned by digest"
