# Deploying SafeRun AI

SafeRun executes untrusted code by starting a Docker container per request.
That single fact decides where it can run.

## The hard requirement: a Docker daemon you control

The backend talks to Docker through the socket at `/var/run/docker.sock`. It
needs to create, wait on and remove containers. Managed "web service" products
that only run your image -- Render, Railway's default web service, Vercel,
Cloud Run -- do not give you a Docker daemon, so the API starts, passes
`/health`, and then fails every `/execute` with `docker_unavailable`.

An earlier `render.yaml` in this repository claimed otherwise. It was removed
because it could never have worked.

Places that do work:

| Target | How |
| --- | --- |
| A VM (Hetzner, DigitalOcean, EC2, an on-prem box) | `docker compose up -d` with the socket mounted |
| Fly.io | a Machine with the Docker socket, or a remote sandbox provider |
| Local machine | `docker compose up` or `uvicorn backend.main:app` |

## 1. Generate an API key first

Nothing that scans, executes or reads history answers without one:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Put it in `.env` as `SAFERUN_API_KEYS`. Comma separate several keys to rotate
them without downtime. If you deliberately want an unauthenticated local
instance, set `SAFERUN_ALLOW_ANONYMOUS=1` -- never on a public host.

## 2. Run it

```bash
cp .env.example .env      # then fill in SAFERUN_API_KEYS
docker compose up --build -d
curl -H "X-API-Key: $KEY" http://localhost:8000/health
```

## 3. Put TLS in front of it

The API key travels in a header, so serve the API over HTTPS. A Caddy or nginx
reverse proxy in front of port 8000 is enough; terminate TLS there and keep
8000 bound to localhost.

## Security notes

- **The socket mount is root on the host.** Anyone who can create containers
  on that daemon can mount the host filesystem. Keep the backend on a host
  that holds nothing else, or put a socket proxy in front of it.
- **Never publish port 8000 without `SAFERUN_API_KEYS` set.** The API will
  refuse to work (503), but do not rely on that alone.
- **Overrides are admin-only.** `override: true` on blocked code needs
  `X-Admin-Key` matching `SAFERUN_ADMIN_KEY`. Leave that variable empty to
  disable overrides completely.
- **Cap the output.** `SAFERUN_MAX_OUTPUT_BYTES` (default 64 KB) bounds what a
  single program can return; `SAFERUN_MAX_CONCURRENT` (default 4) bounds how
  many run at once.
