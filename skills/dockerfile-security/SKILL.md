---
name: dockerfile-security
description: Lint Dockerfiles and Containerfiles for security problems with a stdlib script - containers running as root, unpinned or :latest base images, secrets baked into ENV/ARG or RUN (values never printed), ADD from URLs without checksums, curl piped to sh, .env and private keys copied into the image, disabled TLS verification, chmod 777, sudo, EXPOSE 22 and COPY . without .dockerignore - then rewrite the Dockerfile with multi-stage builds, BuildKit secret mounts, a non-root user and pinned digests. Use when the user asks to review, harden or secure a Dockerfile, "is my Docker image secure", how to pass build secrets (npm token, GitHub token) safely, or why an image leaks credentials in docker history.
license: MIT
compatibility: Python 3.8+ standard library. Docker/BuildKit only for the optional verification step.
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# Dockerfile security

Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

## When to use

- The user shares a `Dockerfile`, `Containerfile` or `*.Dockerfile`, or asks to harden one
- "How do I pass my NPM_TOKEN / GITHUB_TOKEN to docker build safely?"
- "Can someone see secrets in my image?", a scanner flagged root user or secrets in layers
- Preparing an image for production or a public registry

## When not to use

- CVEs in OS packages or libraries inside a built image: use an image scanner (Trivy, Grype,
  Docker Scout) and `dependency-audit` for app dependencies
- docker-compose / Kubernetes runtime settings (capabilities, read-only root, network policy):
  review those manifests separately; see the runtime notes in the reference
- Hunting secrets across the whole repo: `secrets-scan`

## Workflow

1. **Find the Dockerfiles** and the build context (usually the directory with the Dockerfile;
   check CI or compose `build.context`).
2. **Lint (read-only).**
   ```bash
   python3 scripts/dockerfile_lint.py .                       # finds Dockerfile*, *.Dockerfile, Containerfile
   python3 scripts/dockerfile_lint.py docker/api.Dockerfile --context .
   python3 scripts/dockerfile_lint.py . --json --fail-on high
   ```
   Exit 1 = findings at or above `--fail-on` (default medium), 2 = no Dockerfile / bad path.
   Secret values are never printed, only variable names.
3. **Treat secret findings as leaks.** ENV, ARG values and RUN command lines are stored in the
   image config and history (`docker history --no-trunc`) and anyone who can pull the image can
   read them. If an affected image was pushed to a registry, the secret must be rotated (see
   the rotation guide in the `secrets-scan` skill) - rebuilding is not enough.
4. **Add context the linter cannot see**: does the app need root (binding ports < 1024 can be
   solved with a higher port), what does the final stage really need, is there a
   `.dockerignore`, are images pulled from a trusted registry, is the base image maintained?
5. **Rewrite** using [references/hardened-dockerfile.md](references/hardened-dockerfile.md):
   multi-stage build, pinned base (tag + digest), `RUN --mount=type=secret` for build secrets,
   unprivileged `USER`, `COPY` instead of `ADD`, checksum-verified downloads, minimal final
   image, `.dockerignore`. Keep the user's build behaviour; explain each change.
6. **Verify** if Docker is available and the user agrees: build, then
   `docker history --no-trunc IMAGE | grep -iE 'token|secret|password'` (should be empty) and
   `docker run --rm IMAGE id -u` (should not be 0). Re-run the linter.

## Output

```
dockerfile lint: 1 file(s), 3 high, 8 medium, 4 low, 1 info
HIGH   Dockerfile:3   DF003 ARG GITHUB_TOKEN has a default secret value; build args are visible in image history
HIGH   Dockerfile:10  DF006 secret file copied into the image: .env
MEDIUM Dockerfile:1   DF001 base image 'node' is not tagged
MEDIUM Dockerfile:15  DF002 final USER is root
...
Rewritten Dockerfile (diff) + .dockerignore, and: "GITHUB_TOKEN was in image history of
registry.example.com/app:1.4 -> rotate it".
```

## Rule reference

| Rule | Severity | Meaning |
| --- | --- | --- |
| DF001 | medium / info | base image untagged or `:latest` (info: comes from a build arg) |
| DF002 | medium | final stage runs as root |
| DF003 | high / medium | secret in ENV, ARG or RUN |
| DF004 | medium / low | ADD from URL without `--checksum`; ADD for plain files |
| DF005 | medium | `curl ... \| sh` |
| DF006 | high | `.env`, keys, `.npmrc`, credentials copied into the image |
| DF007 | medium | TLS verification disabled |
| DF008 | medium / low | world-writable permissions; `sudo` |
| DF009 | low | `EXPOSE 22` |
| DF010 | low | `COPY .` without `.dockerignore` |
| DF011 | medium | `RUN --security=insecure` |
| DF012 | info | no `HEALTHCHECK` |
