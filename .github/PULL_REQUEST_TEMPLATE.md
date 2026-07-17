## Outcome

Describe the user/security outcome and the smallest relevant scope.

## Changes

-

## Security and privacy review

- [ ] Authorization/workspace scope is enforced server-side.
- [ ] Fail-open/fail-closed behavior is explicit.
- [ ] Logs, fixtures, screenshots, and tests contain no real secrets/private data.
- [ ] New payload storage, telemetry, network access, mounts, or command execution is documented.
- [ ] Security-sensitive behavior has positive and negative regression tests.

## Protocol and compatibility

- [ ] Request ID, cancellation, timeout, size-limit, and extension behavior remains correct or is documented.
- [ ] `docs/PROTOCOL_SUPPORT.md` is updated when support changes.

## Verification

List exact commands and results. Do not mark commands that were not run.

- [ ] `make lint`
- [ ] `make test`
- [ ] `make build`
- [ ] `make docs`
- [ ] `make screenshots` when UI output changed

## Documentation / migration / rollback

State required migrations, configuration changes, rollout order, rollback, and documentation updates. Use “none” only with a reason.
