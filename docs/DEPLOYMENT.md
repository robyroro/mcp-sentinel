# Deployment

## Local Compose

```bash
cp .env.example .env
docker compose up --build
docker compose exec api alembic upgrade head
docker compose exec api python -m mcp_sentinel_api.seed_cli --force
```

Default development endpoints are the console at `http://localhost:3000`, API/OpenAPI at `http://localhost:8000/docs`, gateway at `http://localhost:8080/mcp`, Mailpit at `http://localhost:8025`, and MinIO at `http://localhost:9001`.

Optional profiles:

```bash
docker compose --profile sandbox up --build
docker compose --profile observability up --build
```

## Production checklist

1. Terminate TLS at a maintained reverse proxy and restrict management and gateway ingress separately.
2. Replace every development credential and load secrets through a secret manager; do not bake `.env` into images.
3. Use managed or replicated PostgreSQL with encrypted backups, point-in-time recovery, and tested restores.
4. Configure Redis authentication/TLS and persistence appropriate for jobs; approval truth remains in PostgreSQL.
5. Use versioned S3 storage with encryption and lifecycle rules; use object lock for evidence requirements.
6. Store Ed25519 signing material in KMS/HSM or a restricted signing service and retain public keys.
7. Run gateways and workers with least-privilege identities and egress rules. Isolate sandbox workers onto dedicated hosts.
8. Configure cookie `Secure`, external URLs, trusted origins/hosts, internal gateway authentication, retention, and payload mode.
9. Add rate limits/WAF controls outside the app and alerts for denials, critical risk, audit lag, approval backlog, and sandbox failures.
10. Pin images by digest, scan them, stage migrations, and practice rollback before upgrades.

## High availability

Gateway replicas are stateless for ordinary HTTP requests, but live streams remain bound to one connection. PostgreSQL coordinates durable approval decisions; Redis transports background work. Run health probes separately from deep dependency readiness so a database incident does not create an uncontrolled enforcement bypass.

## Backups and recovery

Back up PostgreSQL, object artifacts, policy bundles, encryption metadata, and public signing keys. Secret-provider source material follows the provider's process. After recovery, verify the latest audit chain/export and ensure expired approvals cannot resume.

## Upgrades

Read [`CHANGELOG.md`](../CHANGELOG.md), back up, run Alembic migrations as a single deployment step, deploy API/workers, then gateways and web. Version policies and risk weights before behavioral changes. Never downgrade the database without a tested migration path.
