# Troubleshooting

## Services do not become healthy

Run `docker compose ps` and `docker compose logs SERVICE`. Confirm ports 3000, 8000, 8080, 5432, 6379, 9000/9001, and 8025 are available. Recreate development state with `make reset` only if deleting Compose volumes is acceptable.

## Database or migration errors

Verify `SENTINEL_DATABASE_URL`, wait for PostgreSQL health, then run `docker compose exec api alembic upgrade head`. For native SQLite development, ensure the process has write permission and no stale process holds the file.

## Login or CSRF failure

Use the seeded demo identity exactly, clear only the local Sentinel cookie, and verify the console and API URLs match `.env`. Production HTTPS requires `SENTINEL_COOKIE_SECURE=true`; HTTP development requires `false`.

## Gateway denies every request

Check API health, `SENTINEL_GATEWAY_API_TOKEN`, policy assignment, upstream URL/command, and gateway logs. Control-plane failure intentionally fails closed. Use inspect mode only for development and never as a silent production bypass.

## Stdio server exits

Run the configured argument vector directly, confirm it writes protocol frames only to stdout and diagnostics to stderr, and check the JSON-line/message limit. Shell operators are not interpreted because Sentinel does not start the server through a shell.

## Approval never resumes

Confirm it is still pending and unexpired, the reviewer has the required role, and the gateway's bounded polling deadline has not elapsed. A request that timed out/cancelled must be submitted again.

## Sandbox fails

Confirm Docker is running, enable the `sandbox` profile, inspect the socket-proxy health, validate the image/argv/mount roots, and check CPU/memory/PID settings. Do not solve a socket error by mounting the unrestricted Docker socket into the API.

## Browser tests fail

Ensure ports 3011 and 8011 are free, then run `pnpm --dir apps/web test:e2e`. Inspect `apps/web/test-results` and the Playwright trace. Production build must succeed before the configured `next start` test server can launch.

## Audit verification fails

Do not modify/extract/repack the bundle before verification. A failure identifies the manifest, signature, file hash, or chain link. Preserve the original artifact and investigate signing-key/version provenance.

## Documentation links fail

Run `make docs`. The checker validates local Markdown links, required screenshots, and Mermaid fence balance; external links are not fetched during this deterministic check.
