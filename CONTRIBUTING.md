# Contributing to MCPIDS

Thanks for taking the time to contribute. This project aims to be practical,
security-focused infrastructure for inspecting MCP traffic inline.

## Ways to Contribute

- Report reproducible bugs
- Propose new detection rules, threat fixtures, or schema validation cases
- Improve docs, deployment assets, and demo workflows
- Add tests, performance profiling, and parser hardening
- Implement roadmap items listed in `docs/design.tex` and `docs/limitations.md`

## Before You Start

Please do **not** file public issues for vulnerabilities. Use
[`SECURITY.md`](./SECURITY.md) for private reporting instead.

For regular bugs and feature requests, open an issue first when the change is
non-trivial. Small fixes and documentation improvements can go directly to a PR.

## Local Setup

Requirements:

- Go 1.23+
- Docker + Docker Compose
- Make
- `python3` for the local demo script
- `buf` only if you change protobuf definitions

Bootstrap:

```bash
make docker-up
make migrate
make seed
```

Run a quick local demo:

```bash
./scripts/demo-local.sh
```

## Development Workflow

Create a branch and keep the change focused:

```bash
git checkout -b feature/my-change
```

Run the relevant checks before opening a PR:

```bash
make test-unit
make test-integration
make test-integration-infra
make test-threats
```

If you touch protobuf definitions, regenerate the checked-in stubs:

```bash
make generate
```

If you change docs that include generated PDFs, rebuild and commit both source
and generated artifacts together.

## Coding Guidelines

- Prefer small, reviewable patches with tests
- Keep gateway hot-path logic fail-closed unless a config explicitly opts out
- Do not weaken tenant scoping, audit persistence, or policy enforcement for
  convenience
- Default to standard Go formatting and avoid introducing broad refactors in
  behavior fixes
- Update `README.md`, `docs/`, and threat fixtures when user-visible behavior
  changes

## Pull Request Checklist

- [ ] The PR has a clear summary and rationale
- [ ] Tests were added or updated for behavior changes
- [ ] `make test-unit` passes
- [ ] `make test-integration` passes
- [ ] `make test-integration-infra` was run for persistence or Redis changes
- [ ] Docs and examples were updated when needed
- [ ] No secrets, credentials, or private customer data are included

## Release Process

Maintainers publish releases by pushing an annotated tag:

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

The `release` workflow builds release archives, generates checksums and an
SBOM, publishes a GitHub Release, and pushes component images to GHCR.

