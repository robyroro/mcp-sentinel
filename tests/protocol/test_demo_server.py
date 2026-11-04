import json
import subprocess
import sys


def exchange(messages: list[dict]) -> list[dict]:
    process = subprocess.Popen(
        [
            sys.executable,
            "examples/demo_mcp_server.py",
            "--profile",
            "safe-filesystem",
            "--transport",
            "stdio",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    payload = "".join(json.dumps(message) + "\n" for message in messages)
    stdout, stderr = process.communicate(payload, timeout=10)
    assert process.returncode == 0, stderr
    return [json.loads(line) for line in stdout.splitlines()]


def test_initialization_capabilities_and_id_preservation():
    messages = [
        {
            "jsonrpc": "2.0",
            "id": "init-42",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": "resource", "method": "resources/list", "params": {}},
        {"jsonrpc": "2.0", "id": "prompt", "method": "prompts/list", "params": {}},
    ]
    responses = exchange(messages)
    assert responses[0]["id"] == "init-42"
    assert responses[0]["result"]["protocolVersion"] == "2025-11-25"
    assert responses[1]["id"] == 7 and responses[1]["result"]["tools"]
    assert responses[2]["result"]["resources"]
    assert responses[3]["result"]["prompts"]


def test_tool_input_error_is_tool_result_error():
    responses = exchange(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "filesystem.read_file", "arguments": {"path": ".env"}},
            }
        ]
    )
    assert responses[0]["result"]["isError"] is True


def test_virtual_workspace_path_maps_to_synthetic_fixture():
    responses = exchange(
        [
            {
                "jsonrpc": "2.0",
                "id": "safe-read",
                "method": "tools/call",
                "params": {
                    "name": "filesystem.read_file",
                    "arguments": {"path": "/workspace/project/README.md"},
                },
            }
        ]
    )
    assert responses[0]["id"] == "safe-read"
    assert responses[0]["result"].get("isError") is not True
    assert "Sentinel" in responses[0]["result"]["content"][0]["text"]
