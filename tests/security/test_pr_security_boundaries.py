import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from mcp_sentinel_api import services
from mcp_sentinel_api.schemas import SandboxRequest
from pydantic import ValidationError
from sentinel_core.policy import Decision, PolicyEngine, PolicyError


def request_with_mount(source: Path, destination="/workspace/data"):
    return SandboxRequest(
        server_id="test",
        profile="no_network",
        image="python:3.12-slim",
        mounts=[{"source": str(source), "destination": destination}],
    )


def test_sandbox_uses_structured_api_and_keeps_restrictions(monkeypatch, tmp_path):
    workspace = tmp_path / "allowed"
    workspace.mkdir()
    project = workspace / "project"
    project.mkdir()
    monkeypatch.setattr(
        services, "get_settings", lambda: SimpleNamespace(sandbox_mount_roots=(workspace,))
    )
    client = MagicMock()
    client.containers.run.return_value.id = "a" * 64
    monkeypatch.setattr(services.docker, "from_env", lambda **kwargs: client)
    sandbox = SimpleNamespace(id="synthetic-sandbox", container_id=None)
    manager = services.DockerSandboxManager()
    assert manager.start(MagicMock(), sandbox, request_with_mount(project)) == "a" * 64
    options = client.containers.run.call_args.kwargs
    assert options["read_only"] is True
    assert options["network"] == "none"
    assert options["cap_drop"] == ["ALL"]
    assert options["security_opt"] == ["no-new-privileges:true"]
    assert options["user"] == "65532:65532"
    assert options["mounts"][0]["Source"] == str(project.resolve())
    assert options["mounts"][0]["ReadOnly"] is True
    assert options["pids_limit"] == 64
    client.close.assert_called_once()


@pytest.mark.parametrize(
    "kind", ["no-roots", "outside", "prefix-sibling", "credential", "traversal-target"]
)
def test_sandbox_rejects_unsafe_mount_before_contacting_docker(monkeypatch, tmp_path, kind):
    root = tmp_path / "allowed"
    root.mkdir()
    source = root / "project"
    source.mkdir()
    destination = "/workspace/data"
    roots = (root,)
    if kind == "no-roots":
        roots = ()
    elif kind == "outside":
        source = tmp_path / "outside"
        source.mkdir()
    elif kind == "prefix-sibling":
        source = tmp_path / "allowed-other"
        source.mkdir()
    elif kind == "credential":
        source = root / ".ssh"
        source.mkdir()
    else:
        destination = "/workspace/../etc"
    monkeypatch.setattr(
        services, "get_settings", lambda: SimpleNamespace(sandbox_mount_roots=roots)
    )
    connect = MagicMock()
    monkeypatch.setattr(services.docker, "from_env", connect)
    with pytest.raises(ValueError):
        services.DockerSandboxManager().start(
            MagicMock(), SimpleNamespace(id="test"), request_with_mount(source, destination)
        )
    connect.assert_not_called()


def test_image_cannot_be_a_docker_option():
    with pytest.raises(ValidationError):
        SandboxRequest(server_id="test", profile="no_network", image="--privileged")


def test_mount_symlink_cannot_escape_an_allowed_root(monkeypatch, tmp_path):
    root, outside = tmp_path / "allowed", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    link = root / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("creating symlinks requires a platform privilege")
    monkeypatch.setattr(
        services, "get_settings", lambda: SimpleNamespace(sandbox_mount_roots=(root,))
    )
    with pytest.raises(ValueError, match="symlink"):
        services.DockerSandboxManager().build_options(request_with_mount(link), "synthetic")


def test_docker_errors_do_not_leak_daemon_details(monkeypatch):
    connect = MagicMock(side_effect=services.docker.errors.DockerException("private-daemon-detail"))
    monkeypatch.setattr(services.docker, "from_env", connect)
    request = SandboxRequest(server_id="test", profile="no_network", image="python:3.12-slim")
    with pytest.raises(RuntimeError) as error:
        services.DockerSandboxManager().start(MagicMock(), SimpleNamespace(id="test"), request)
    assert "private-daemon-detail" not in str(error.value)


def test_seed_cli_never_prints_returned_credentials(monkeypatch, capsys):
    from mcp_sentinel_api import seed_cli

    monkeypatch.setattr(seed_cli.Base.metadata, "create_all", MagicMock())
    monkeypatch.setattr(seed_cli, "SessionLocal", MagicMock())
    seed = MagicMock(return_value={"status": "seeded", "demo_password": "must-stay-private"})
    monkeypatch.setattr(seed_cli, "seed_database", seed)
    seed_cli.main()
    assert "must-stay-private" not in capsys.readouterr().out
    seed.assert_called_once()


def test_regex_is_linear_time_and_preserves_policy_semantics():
    document = {
        "version": "1",
        "name": "regex",
        "defaults": {"decision": "deny"},
        "rules": [
            {"id": "match", "action": "allow", "match": {"tool": {"regex": "^(a+)+$"}}},
        ],
    }
    engine = PolicyEngine(document)
    assert engine.evaluate({"tool": "a" * 100_000 + "!"}).decision is Decision.DENY
    assert engine.evaluate({"tool": "aaa"}).decision is Decision.ALLOW
    document["rules"][0]["match"]["tool"]["regex"] = r"(a)\1"
    with pytest.raises(PolicyError):
        PolicyEngine(document)


def demo_module(monkeypatch, tmp_path):
    path = Path("examples/demo_mcp_server.py")
    specification = importlib.util.spec_from_file_location("demo_pr_security", path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.setattr(module, "ROOT", root.resolve())
    return module


def test_demo_boundary_rejects_traversal_and_redacts_errors(monkeypatch, tmp_path):
    demo = demo_module(monkeypatch, tmp_path)
    outside = tmp_path / "workspace-other"
    outside.mkdir()
    (outside / "private.txt").write_text("outside data")
    result = demo.call_tool(
        "safe-filesystem", "filesystem.read_file", {"path": str(outside / "private.txt")}
    )
    assert result["isError"] is True
    assert "outside data" not in str(result)
    assert str(tmp_path) not in str(result)
    with pytest.raises(ValueError):
        demo.safe_path("../workspace-other/private.txt")
    assert (
        demo.call_tool(
            "safe-filesystem",
            "filesystem.write_file",
            {"path": "/workspace/project/new.txt", "content": "safe"},
        ).get("isError")
        is not True
    )
    assert (demo.ROOT / "new.txt").read_text() == "safe"
