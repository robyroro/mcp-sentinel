# MCP protocol support

The gateway targets MCP protocol revision `2025-11-25`. Compatibility is intentionally described narrowly: a server or client can use protocol features not interpreted by Sentinel only when their JSON values can be safely forwarded within configured limits.

## Capability matrix

| Capability | Status | Transport | Notes |
|---|---|---|---|
| Initialization and version negotiation | Supported | stdio, Streamable HTTP | IDs, negotiated version, capabilities, and safe extensions preserved |
| JSON-RPC requests/responses/errors | Supported | stdio, Streamable HTTP | structural validation, bounded frames, gateway/client/server error separation |
| Tools list and call | Supported | stdio, Streamable HTTP | policy/risk enforcement and response inspection on JSON responses |
| Resources list/read | Supported | stdio, Streamable HTTP | method and URI policy matching supported |
| Prompts list/get | Supported | stdio, Streamable HTTP | discovery and forwarding supported |
| Notifications | Pass-through | stdio, Streamable HTTP | valid messages forwarded; no response is fabricated |
| Cancellation | Supported forwarding | stdio, Streamable HTTP | cancellation notification is forwarded; local deadline also cancels the wait |
| Progress notifications | Pass-through | stdio, Streamable HTTP | safe extension fields preserved; progress is not aggregated in the UI |
| Streamable HTTP POST | Supported | HTTP | request proxy and security evaluation |
| Streamable HTTP GET/SSE | Compatibility support | HTTP/SSE | upstream stream is proxied; individual SSE events are not yet content-inspected |
| Streamable HTTP DELETE | Supported | HTTP | forwarded for session termination |
| Legacy HTTP+SSE transport | Not implemented | — | use a compatible adapter if required |
| WebSocket adapter | Not implemented | — | roadmap item; no support claim |
| MCP Tasks semantics | Pass-through only | supported transports | no task-aware persistence or UI |
| Elicitation/sampling semantics | Pass-through only | supported transports | policy can match method; payload-specific UX is not implemented |

## Transport safety

- Stdio uses one JSON-RPC message per line, supervises the child without a shell, forwards stderr separately, enforces line/message size, and terminates on bounded shutdown.
- Streamable HTTP validates allowed methods, content type/body size, configured origin policy, upstream timeout, and response size for JSON bodies.
- Request IDs retain their JSON type. Notifications without IDs do not receive synthetic replies.
- Unknown top-level fields are retained when safe; fields do not bypass the evaluated method and parameters.

## Compatibility tests

`tests/protocol` covers valid/invalid JSON-RPC fixtures, initialization, discovery, request IDs, errors, message limits, cancellation shapes, and safe extension preservation. `apps/gateway` includes Go transport/handler tests. The synthetic server in `examples/demo_mcp_server.py` supports initialization, ping, tools, resources, prompts, notifications, and cancellation fixtures.

## Known limitations

SSE streams are proxied but not parsed event-by-event for redaction. HTTP resumability and `Last-Event-ID` semantics depend on the upstream server. Server-to-client requests are structurally proxied but do not have specialized approval UX. Experimental or future protocol methods are not claimed as fully understood merely because their JSON can pass through.
