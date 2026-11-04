# Sandbox security

The optional sandbox manager launches untrusted local MCP servers through the Docker API using a fixed argument vector. Sandbox mode reduces host exposure but is not a perfect isolation boundary because containers share the host kernel.

## Default controls

- non-root runtime user;
- read-only root filesystem where compatible;
- all Linux capabilities dropped;
- `no-new-privileges`;
- bounded CPU, memory, PID count, and runtime;
- explicit read-only/read-write mounts with normalized host paths;
- no network or an explicit allowlisted network profile;
- temporary writable `tmpfs` rather than broad host mounts;
- health and MCP initialization deadline;
- bounded stop followed by kill and cleanup;
- no shell interpolation and no plaintext secret logging.

## Docker access

The production-shaped Compose profile uses a Docker socket proxy with a narrow API surface. Treat even proxied Docker access as highly privileged. Run the sandbox manager on a dedicated host or VM for hostile workloads, restrict accepted images, pin digests, and avoid mounting sensitive host directories.

## Mount rules

Host paths must resolve beneath operator-configured roots. Deny the Docker socket, device files, system roots, credential directories, and writable repository mounts unless explicitly required. Symlink and filesystem race defenses should be complemented with read-only bind mounts and a dedicated sandbox filesystem.

Set `SENTINEL_SANDBOX_MOUNT_ROOTS` to a JSON array of dedicated absolute host directories, for example `["/srv/sentinel/workspaces"]`. The default is an empty allowlist, which rejects every bind mount. Both the requested path and its resolved symlink target must be beneath an allowed root; credential directories and Docker socket paths are rejected. Mount destinations must remain inside `/workspace/`. Container creation/removal uses the Docker SDK's structured API, so image and mount values are never parsed as CLI options. This does not remove host-filesystem race risks or make containers a VM boundary.

## Network rules

`network=none` is preferred. When egress is needed, enforce it outside the container with a firewall/proxy that blocks loopback, link-local, private ranges, cluster control planes, and cloud metadata. Application-layer DNS checks alone are vulnerable to rebinding and TOCTOU changes.

## Stronger isolation

For multitenant or hostile public packages, use a dedicated VM, microVM, gVisor/Kata-style runtime, separate kernel, and restricted egress. Kubernetes and VM-based isolation are roadmap items, not current features.
