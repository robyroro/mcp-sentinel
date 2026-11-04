# CLI

Install the editable project or wheel, then run `mcp-sentinel --help`.

```bash
mcp-sentinel status
mcp-sentinel login --email admin@example.com
mcp-sentinel server list
mcp-sentinel server scan SERVER_ID
mcp-sentinel client configure safe-filesystem
mcp-sentinel policy validate examples/policy-examples/coding-agent-restricted.yaml
mcp-sentinel policy test POLICY.yaml REQUEST.json
mcp-sentinel session list
mcp-sentinel session inspect SESSION_ID
mcp-sentinel replay simulate SESSION_ID POLICY.yaml
mcp-sentinel approvals list
mcp-sentinel approvals approve APPROVAL_ID VERSION --justification "Reviewed scope"
mcp-sentinel approvals deny APPROVAL_ID VERSION --justification "Outside workspace"
mcp-sentinel sandbox list
mcp-sentinel audit export
mcp-sentinel audit verify audit-bundle.zip
```

Login stores the signed session and CSRF value in the operating-system credential store, not a plaintext dotfile. The CLI refuses server credentials on command lines. Use `--json` where available for automation and set `SENTINEL_API_URL` for a non-default control plane.

Policy validation and audit-bundle verification run locally. Management commands use the same workspace/RBAC checks as the browser. CI should use a dedicated short-lived service identity rather than a human session when that adapter is configured.
