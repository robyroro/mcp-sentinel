# API

The FastAPI management/control API is served at `/api/v1`; interactive OpenAPI is available at `/docs` in local development.

## Endpoint groups

| Group | Representative routes |
|---|---|
| Health/auth | `GET /health`, `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` |
| Dashboard/inventory | `GET /dashboard`, `/servers`, `/tools`, `/clients` |
| Policies | `GET /policies`, `POST /policies/test` |
| Sessions/events | `GET /sessions`, `GET /sessions/{id}`, `GET /sessions/{id}/events` |
| Approvals | `GET /approvals`, `POST /approvals/{id}/decision` |
| Security | `GET /risk`, `/secrets`, `/sandbox` |
| Evidence | `GET /reports`, `POST /reports`, `GET /audit`, audit export/verification routes |
| Settings/metrics | `GET /settings`, `GET /metrics` |
| Gateway internal | policy evaluation, approval polling, response inspection |

The generated OpenAPI document is the exact request/response reference.

## Authentication and mutation

Browser/CLI requests authenticate with a signed HttpOnly session cookie. State-changing requests require `X-CSRF-Token`; idempotent business actions should also send `Idempotency-Key`. Workspace scope and role are derived server-side. Do not place credentials in URLs.

```bash
curl -i -c cookies.txt \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"SentinelDemo!2026"}' \
  http://localhost:8000/api/v1/auth/login
```

Use the returned CSRF token and cookie for subsequent local requests. The demo password is synthetic and must not be reused.

## Errors

Validation errors use standard FastAPI problem bodies. Authorization failures are `401`/`403`, optimistic approval conflicts are `409`, missing resources are `404`, and gateway evaluation failures are explicit safe denials. Responses include/request a request ID for audit correlation.

## Internal routes

Gateway evaluation endpoints require `SENTINEL_GATEWAY_API_TOKEN` in the local environment. They are not public management APIs. In production, isolate them on a private listener/network and prefer mTLS or workload identity.
