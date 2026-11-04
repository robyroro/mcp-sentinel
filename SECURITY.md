# Security policy

## Supported versions

Security fixes are provided for the latest tagged minor release. The `main` branch is development code and may change without notice.

## Report a vulnerability

Do not open a public issue. Use GitHub private vulnerability reporting for this repository. Include affected version, deployment mode, reproduction steps using synthetic data, impact, and suggested mitigation. Do not access data or systems you do not own.

Maintainers aim to acknowledge reports within five business days, validate and establish severity within ten, and coordinate a fix and disclosure timeline. Timelines may vary for protocol or dependency coordination.

## Security scope

High-priority reports include policy/approval bypass, workspace isolation failure, secret plaintext persistence, authentication or CSRF bypass, gateway fail-open behavior, audit/signature forgery, sandbox escape caused by Sentinel configuration, SSRF bypass, path escape, and command injection.

Prompt-injection or secret-pattern false positives/negatives without a control bypass are usually hardening reports, not vulnerabilities. Containers are documented as a shared-kernel boundary.

Never include a real secret in a report. Use an unmistakably synthetic fixture.
