# Human approvals

Approvals pause a gateway request when a policy returns `require_approval`. The control plane stores the sanitized original arguments, requesting identity, client/server/session, policy rule, risk evidence, expected side effects, expiry, and a stable request fingerprint.

## Decisions

Authorized reviewers can approve once, approve for the session, approve modified arguments, approve a similar pattern for a limited window, deny, deny and block the pattern, or escalate. The current demo UI fully exercises approve-once, argument modification, denial, and escalation state; longer-lived pattern grants are represented as bounded policy context and should be reviewed like policy changes.

## Authorization

Owners, Administrators, and Security Reviewers may decide approvals in their workspace. Developers can request and inspect their own sessions; Auditors and Viewers are read-only. Every decision is checked server-side regardless of UI state.

## Concurrency and lifecycle

- Creation is idempotent for the request fingerprint.
- A decision uses an atomic conditional update on `pending` plus an optimistic version.
- A losing reviewer receives a conflict and the accepted decision.
- Expired, cancelled, or disconnected requests cannot later be approved into execution.
- Gateway polling is bounded; timeout and control-plane failure deny the request.
- A gateway restart can query durable approval state, but forwarding remains bound to the original request lifecycle.

## Argument changes

The detail view presents a structured diff. Only the reviewed arguments are returned to the gateway; method, server, identity, and request ID cannot be changed by an argument approval. The gateway performs inspection again before forwarding and inspects the response afterward.

## Notifications

In-app state is authoritative. The worker includes webhook/development-mail adapter boundaries, but external delivery is intentionally a local adapter stub until an operator configures a real destination. Notifications must contain summaries and links, not raw secrets or complete payloads.

## Operational guidance

Use short expirations, small reviewer groups, separation of duties for critical systems, and out-of-band verification for financial/deployment actions. An approval is evidence of a human decision, not proof the action is harmless.
