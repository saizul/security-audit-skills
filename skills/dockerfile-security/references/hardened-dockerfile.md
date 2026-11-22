# Hardened Dockerfile patterns

## Node.js example (multi-stage, build secret, non-root)

```dockerfile
# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim@sha256:<digest> AS build
WORKDIR /src
COPY package.json package-lock.json ./
# Secret is mounted only for this RUN; it is not stored in a layer or the history.
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN="$(cat /run/secrets/npm_token)" npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

FROM node:22-bookworm-slim@sha256:<digest>
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=node:node /src/dist ./dist
COPY --from=build --chown=node:node /src/node_modules ./node_modules
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD node dist/healthcheck.js
CMD ["node", "dist/server.js"]
```

Build: `docker build --secret id=npm_token,env=NPM_TOKEN -t app .`
(`.npmrc` can reference `${NPM_TOKEN}`; do not COPY a `.npmrc` that contains the token.)

## Python example

```dockerfile
# syntax=docker/dockerfile:1
FROM python:3.12-slim@sha256:<digest> AS build
WORKDIR /src
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

FROM python:3.12-slim@sha256:<digest>
RUN useradd --system --uid 10001 --no-create-home app
WORKDIR /app
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index /wheels/* && rm -rf /wheels
COPY --chown=app:app src/ ./src/
USER 10001
CMD ["python", "-m", "src.main"]
```

## Rules of thumb

- **Pin bases**: a version tag for readability plus a digest for immutability
  (`docker buildx imagetools inspect node:22-bookworm-slim` shows it). Let Dependabot/Renovate
  bump digests.
- **Non-root**: use the image's user (`node`, `nginx` unprivileged variants) or create one
  with a fixed UID; prefer a numeric `USER 10001` so Kubernetes `runAsNonRoot` can verify it.
- **Build secrets**: `RUN --mount=type=secret` (BuildKit) or `--mount=type=ssh` for private Git.
  Never `ARG`/`ENV` for tokens, never COPY credential files, never `echo $TOKEN > ~/.npmrc` in
  a layer (even if removed in a later layer, it remains in the earlier one).
- **Downloads**: `ADD --checksum=sha256:<hash> https://...` or
  `curl -fsSLo tool.tgz URL && echo "<hash>  tool.tgz" | sha256sum -c -`. Prefer distro
  packages or official images over piping install scripts to a shell.
- **COPY not ADD** for local files; `ADD` auto-extracts archives and fetches URLs.
- **Small final image**: multi-stage, `-slim`/distroless/`scratch` final stage, no compilers,
  package caches removed in the same `RUN` that created them.
- **.dockerignore**:
  ```
  .git
  .env*
  !.env.example
  *.pem
  *.key
  node_modules
  __pycache__
  .venv
  dist
  coverage
  ```
- **TLS stays on**: add internal CAs to the trust store (`COPY ca.crt /usr/local/share/ca-certificates/`
  + `update-ca-certificates`) instead of `-k`, `--trusted-host` or `strict-ssl false`.

## Runtime settings (compose / Kubernetes / docker run)

These are outside the Dockerfile but complete the picture:

- `read_only: true` root filesystem with explicit `tmpfs` for writable paths
- `cap_drop: [ALL]`, add back only what is needed; `security_opt: ["no-new-privileges:true"]`
- no `privileged: true`, no Docker socket mount, no host networking
- memory/CPU limits; secrets via the orchestrator's secret mechanism
- Kubernetes: `runAsNonRoot: true`, `allowPrivilegeEscalation: false`,
  `readOnlyRootFilesystem: true`, `seccompProfile: RuntimeDefault`
