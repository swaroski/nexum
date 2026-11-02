---
title: Deploy
description: Docker and Kubernetes.
---

The gateway is one binary plus local files. Run it as a sidecar, a
shared gateway in front of several tools, or on a laptop.

## Docker

```bash
NEXUM_DOMAIN=example.com docker compose -f deploy/docker/docker-compose.yml up -d
curl localhost:8080/healthz                                   # ok
docker compose -f deploy/docker/docker-compose.yml exec nexum nexum doctor
```

The container runs as a non-root user with a read-only root filesystem.
Config, keys, state and audit live in the `nexum-data` volume.

## Kubernetes

A minimal manifest is in
[`deploy/kubernetes/nexum.yaml`](https://github.com/swaroski/nexum/blob/main/deploy/kubernetes/nexum.yaml):
a ConfigMap with `nexum.yaml`, `trust.yaml` and `policy.yaml`, and a hardened
Deployment with health probes.

- **Single replica on purpose in v0.1.** The replay cache and local state are
  per instance; see the [threat model](/nexum/security/threat-model/).
- Keep the organization signing key **out of the cluster**. The gateway only
  needs public keys to verify.
- Use a PersistentVolumeClaim for `/data` to keep audit and state.
- The gateway shuts down gracefully on `SIGTERM`.

## TLS

The gateway warns when it listens on a non-loopback address without TLS.
Terminate TLS in front of it (ingress, service mesh, or reverse proxy).
