# Demo environment

The seed is deterministic and contains 3 workspaces, 6 users, 5 clients, 8 servers, 40 tools, 12 policies, 30 sessions, 520 protocol events, 30 approvals, 15 secret findings, 8 sandboxes, and 5 reports. Every identity, host, repository, token, and payload is synthetic.

## Start

```bash
cp .env.example .env
docker compose up --build
make seed
```

Open `http://localhost:3000` and sign in as `admin@example.com` with `SentinelDemo!2026`. This credential is for the local fixture only.

## Servers and scenarios

- **Safe filesystem:** list/read content below the synthetic workspace.
- **Restricted file:** request `.env`/credential paths and observe a denial.
- **Risky shell:** safe test command can be allowed; destructive fixture is denied.
- **Approval:** a write/message request pauses and appears in the reviewer queue.
- **Fake secret:** a response contains intentionally invalid credential-shaped text and is redacted.
- **Injection fixture:** a resource returns adversarial instructions and receives an injection warning.
- **Private network:** loopback/private/cloud-metadata targets are blocked.
- **Database/messaging:** synthetic mutation and send tools demonstrate side-effect classification.

Run the client with `make demo`. Generate the 24 repository screenshots with `make screenshots`. The test harness resets/seeds its own SQLite database and uses isolated ports, so it does not depend on a developer's current session.

## Safety

Demo tools operate on generated fixtures and do not send mail, access paid APIs, or carry working secrets. The sandbox scenario requires Docker and the optional `sandbox` profile.
