"""Run a native API -> gateway -> demo MCP server vertical smoke test."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
API_PORT = 8012
SERVER_PORT = 9012
GATEWAY_PORT = 8082


def process(command: list[str], environment: dict[str, str]) -> subprocess.Popen[bytes]:
    options: dict[str, Any] = {
        "cwd": ROOT,
        "env": environment,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW
    return subprocess.Popen(command, **options)


def wait_for(url: str, processes: list[subprocess.Popen[bytes]], timeout: float = 40) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        failed = [item for item in processes if item.poll() is not None]
        if failed:
            raise RuntimeError(
                f"service exited before readiness: {[item.returncode for item in failed]}"
            )
        try:
            with urllib.request.urlopen(url, timeout=1):  # noqa: S310 - fixed loopback URL
                return
        except (urllib.error.URLError, TimeoutError):
            time.sleep(0.25)
    raise TimeoutError(f"service did not become ready: {url}")


def rpc(request_id: str, method: str, params: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(  # noqa: S310 - fixed loopback URL
        f"http://127.0.0.1:{GATEWAY_PORT}/mcp/Safe%20Filesystem",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Mcp-Protocol-Version": "2025-11-25",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def stop_all(processes: list[subprocess.Popen[bytes]]) -> None:
    for item in reversed(processes):
        if item.poll() is None:
            item.terminate()
    for item in reversed(processes):
        try:
            item.wait(timeout=5)
        except subprocess.TimeoutExpired:
            item.kill()
            item.wait(timeout=5)


def main() -> int:
    gateway = (
        ROOT
        / "bin"
        / ("sentinel-gateway-verify.exe" if os.name == "nt" else "sentinel-gateway-verify")
    )
    if not gateway.exists():
        raise FileNotFoundError(f"build the gateway first: {gateway}")
    database = ROOT / "vertical-verify.db"
    database.unlink(missing_ok=True)
    base = os.environ.copy()
    api_env = {
        **base,
        "SENTINEL_DATABASE_URL": f"sqlite:///{database.as_posix()}",
        "SENTINEL_GATEWAY_API_TOKEN": "vertical-test-gateway-token",
        "SENTINEL_SIGNING_KEY_PATH": str(ROOT / ".sentinel" / "vertical-signing-key.pem"),
    }
    gateway_env = {
        **base,
        "SENTINEL_API_URL": f"http://127.0.0.1:{API_PORT}",
        "SENTINEL_GATEWAY_API_TOKEN": "vertical-test-gateway-token",
        "SENTINEL_UPSTREAM_URL": f"http://127.0.0.1:{SERVER_PORT}/mcp",
        "SENTINEL_GATEWAY_LISTEN": f"127.0.0.1:{GATEWAY_PORT}",
        "SENTINEL_SERVER_NAME": "Safe Filesystem",
        "SENTINEL_CLIENT_ID": "codex-local",
        "SENTINEL_WORKSPACE": "acme-security",
    }
    processes: list[subprocess.Popen[bytes]] = []
    try:
        processes.append(
            process(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "mcp_sentinel_api.main:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(API_PORT),
                ],
                api_env,
            )
        )
        processes.append(
            process(
                [
                    sys.executable,
                    "examples/demo_mcp_server.py",
                    "--profile",
                    "safe-filesystem",
                    "--transport",
                    "http",
                    "--port",
                    str(SERVER_PORT),
                ],
                base,
            )
        )
        wait_for(f"http://127.0.0.1:{API_PORT}/api/v1/health", processes)
        processes.append(process([str(gateway), "http"], gateway_env))
        wait_for(f"http://127.0.0.1:{GATEWAY_PORT}/healthz", processes)

        status, initialized = rpc(
            "init-string-id",
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "vertical-smoke", "version": "1.0.0"},
            },
        )
        assert status == 200 and initialized["id"] == "init-string-id", (status, initialized)
        assert initialized["result"]["protocolVersion"] == "2025-11-25"

        status, tools = rpc("list-tools", "tools/list", {})
        assert status == 200 and len(tools["result"]["tools"]) == 3, (status, tools)

        status, safe = rpc(
            "safe-read",
            "tools/call",
            {
                "name": "filesystem.read_file",
                "arguments": {"path": "/workspace/project/README.md"},
            },
        )
        assert status == 200 and "Sentinel" in safe["result"]["content"][0]["text"], (
            status,
            safe,
        )

        status, denied = rpc(
            "restricted-read",
            "tools/call",
            {
                "name": "filesystem.read_file",
                "arguments": {"path": "/workspace/project/.env"},
            },
        )
        assert status == 403 and denied["error"]["code"] == -32002, (status, denied)
        print(
            json.dumps(
                {
                    "initialize": "passed",
                    "tools_discovered": len(tools["result"]["tools"]),
                    "safe_tool_call": "passed",
                    "restricted_path": "blocked",
                    "request_ids_preserved": True,
                }
            )
        )
        return 0
    finally:
        stop_all(processes)
        database.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
