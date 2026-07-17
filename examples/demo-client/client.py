from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from urllib.parse import urlparse


def call(endpoint: str, request_id: int, method: str, params: dict) -> dict:
    if urlparse(endpoint).scheme not in {"http", "https"}:
        raise ValueError("demo client endpoint must use http or https")
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(  # noqa: S310 - scheme allowlisted above
        endpoint,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Mcp-Protocol-Version": "2025-11-25",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:  # noqa: S310
            return json.load(response)
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read())


def main() -> None:
    parser = argparse.ArgumentParser(description="Run deterministic MCP Sentinel demo scenarios.")
    parser.add_argument("--endpoint", default="http://localhost:8080/mcp/Safe%20Filesystem")
    args = parser.parse_args()
    scenarios = [
        (
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "sentinel-demo-client", "version": "1.0.0"},
            },
        ),
        ("tools/list", {}),
        (
            "tools/call",
            {"name": "filesystem.read_file", "arguments": {"path": "/workspace/project/README.md"}},
        ),
        (
            "tools/call",
            {"name": "filesystem.read_file", "arguments": {"path": "/workspace/project/.env"}},
        ),
        (
            "tools/call",
            {
                "name": "filesystem.write_file",
                "arguments": {
                    "path": "/workspace/project/demo-note.md",
                    "content": "Approved synthetic note",
                },
            },
        ),
    ]
    for request_id, (method, params) in enumerate(scenarios, 1):
        print(
            json.dumps(
                {"request": method, "response": call(args.endpoint, request_id, method, params)},
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
