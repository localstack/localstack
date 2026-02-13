<!--
  Sync Impact Report
  ═══════════════════════════════════════════════
  Version change: 1.1.0 → 1.1.1
  Modified sections:
    - Development Workflow — clarified how to start LocalStack
      for local testing: MUST use `python -m localstack.dev.run`
      from the project's .venv to ensure local code changes are
      mounted correctly into the Docker container.
  Added sections: none
  Removed sections: none
  Templates requiring updates:
    - .specify/templates/plan-template.md ✅ no updates needed
    - .specify/templates/spec-template.md ✅ no updates needed
    - .specify/templates/tasks-template.md ✅ no updates needed
  Follow-up TODOs: none
  ═══════════════════════════════════════════════
-->

# LocalStack Constitution

## Core Principles

### I. AWS Parity First

Every feature implementation MUST target behavioral parity with
real AWS services. This is the project's fundamental value
proposition.

- All service operations MUST match AWS behavior, error codes,
  and response shapes as documented by AWS and validated
  empirically.
- AWS behavior is verified by running the operation against
  real AWS and recording the result as a snapshot test before
  implementing.
- Custom LocalStack-only behaviors MUST NOT be introduced
  unless explicitly justified and clearly documented as
  non-AWS extensions.
- Use botocore service specifications (Smithy models) as the
  source of truth for API shapes and validation rules.

### II. Provider Pattern (ASF)

All AWS service implementations MUST follow the AWS Server
Framework (ASF) provider pattern.

- Providers MUST extend the auto-generated `<Service>Api` class
  from `localstack.aws.api.<service>`.
- Operations MUST use the `@handler` decorator to bind to API
  operations.
- State MUST be managed through the Store pattern
  (`AccountRegionBundle` with `BaseStore` subclass) to ensure
  multi-account and multi-region isolation.
- The files under `aws/api/` are auto-generated and MUST NOT
  be modified manually. Use `python -m localstack.aws.scaffold
  generate <service>` to regenerate.
- Service registration MUST go through the plugin system
  (`plux.ini` via `make entrypoints`).
- **Reference implementation**: See the CodeBuild service
  (`localstack-pro-core/.../codebuild/provider.py` and
  `models.py`) as documented in `AGENTS.md` for the canonical
  `@handler`, `AccountRegionBundle`, and exception patterns.

### III. Parity Testing (NON-NEGOTIABLE)

Tests MUST be validated against real AWS to guarantee parity.
This is the primary quality gate for all service
implementations.

- Every AWS service test MUST use the `@markers.aws.validated`
  marker.
- Snapshot testing is the preferred assertion mechanism: use
  `snapshot.match()` instead of manual assertions where
  applicable.
- Dynamic values (IDs, ARNs, timestamps) MUST be handled with
  snapshot transformers to produce deterministic recordings.
- Tests MUST be runnable against real AWS
  (`TEST_TARGET=AWS_CLOUD`) and LocalStack interchangeably.
- `time.sleep()` is FORBIDDEN in tests. Use `poll_condition`,
  `retry`, or AWS waiters for asynchronous operations.
- Resource creation MUST use fixture factories with automatic
  cleanup. Never create resources in test bodies without
  cleanup guarantees.
- Account IDs and regions MUST NOT be hardcoded; use the
  `account_id` and `region_name` fixtures.
- Test resource names MUST include `short_uid()` for parallel
  execution safety.
- **Reference implementation**: See the Pipes tests
  (`localstack-pro-core/.../pipes/`) as documented in
  `AGENTS.md` for canonical fixture factories, snapshot
  matching, parametrize patterns, and cleanup conventions.

### IV. State Isolation

LocalStack MUST support multi-account and multi-region state
isolation, matching AWS's tenancy model.

- Service stores MUST use `LocalAttribute` for region-scoped
  state, `CrossRegionAttribute` for account-scoped state, and
  `CrossAccountAttribute` for global state.
- Naming convention: region-scoped attributes use lowercase
  names; cross-region and cross-account attributes use
  UPPERCASE names.
- State access MUST go through
  `store[context.account_id][context.region]` — never through
  global variables or module-level singletons.
- Store classes MUST be declared once per service and shared
  between Community and Pro editions.

### V. Simplicity and Convention

Follow established patterns. Avoid unnecessary abstraction and
complexity.

- New service implementations MUST follow the canonical
  structure: `provider.py`, `models.py`, `packages.py`,
  and optionally `resource_providers/`.
- Use `MotoFallbackDispatcher` or `call_moto()` for operations
  not yet implemented rather than returning stub responses.
- Lazy-load imports in plugin registration functions to keep
  startup fast.
- Use existing utilities (`short_uid()`, ARN helpers, polling
  utilities) rather than reimplementing common operations.
- Complexity MUST be justified. If a simpler approach exists
  that satisfies parity requirements, prefer it.
- The development process defined in `AGENTS.md` MUST be
  followed: write a failing test first, find the provider,
  check the store, compare with AWS docs, then iterate.

### VI. AGENTS.md Compliance (NON-NEGOTIABLE)

`AGENTS.md` in the repository root is the authoritative
operational guide for all development on LocalStack. It MUST
be consulted and followed during any implementation work.

- All developers and automated agents MUST read and comply
  with `AGENTS.md` before making changes to the codebase.
- The hard constraints listed in `AGENTS.md` under
  "Critical Hard Constraints" are absolute prohibitions.
  Violating any of them is grounds for rejecting a
  contribution.
- The reference implementations cited in `AGENTS.md` (CodeBuild
  for providers, Pipes for tests) MUST be consulted when
  creating new services or test suites.
- The fixture rules, transformer conventions, and best
  practices in `AGENTS.md` MUST be followed. These include:
  returning entire responses from create operations, storing
  only names/ARNs in cleanup lists, logging cleanup errors,
  and adding transformers before `snapshot.match()`.
- When `AGENTS.md` and this constitution overlap, the more
  specific guidance in `AGENTS.md` takes precedence for
  implementation details. This constitution governs
  architectural principles and governance process.
- Changes to `AGENTS.md` SHOULD be reviewed with the same
  rigor as changes to this constitution, as it directly
  governs development behavior.

## Technical Constraints

- **Language**: Python 3.13+ for core code; Python 3.10+ for
  CLI modules (`localstack/cli/`).
- **Formatting**: Ruff (line length 100). Run `make format`
  before committing.
- **Linting**: Ruff + mypy. Run `make lint` to verify.
- **Dependencies**: Adding new dependencies requires explicit
  justification and review. Use the LocalStack Package Manager
  (LPM) for third-party runtime binaries.
- **Generated code**: `aws/api/` and `plux.ini` are generated
  artifacts. Never edit manually.
- **Snapshot files**: `*.snapshot.json` and `*.validation.json`
  are test-generated. Never edit manually.
- **Hard constraints from AGENTS.md** (reproduced here for
  emphasis — `AGENTS.md` is the canonical source):
  - NEVER modify `*.snapshot.json` or `*.validation.json`
    manually.
  - NEVER use plain `assert` in validated tests — use
    `snapshot.match()`.
  - NEVER create AWS resources directly in test bodies — use
    fixtures.
  - NEVER hardcode account IDs or region names.
  - NEVER modify files in `aws/api/`.
  - NEVER add project dependencies without approval.
  - NEVER run `git push` or modify repository history without
    authorization.

## Development Workflow

- **Canonical process** (from `AGENTS.md`):
  1. Write a failing test first — capture AWS behavior with
     `TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1`.
  2. Find the provider in `services/<service>/provider.py`.
  3. Check the store in `models.py`.
  4. Compare with AWS docs for expected behavior.
  5. Run tests against LocalStack to verify snapshot match.
  6. Iterate: run tests individually, see failures, fix,
     re-run.
- **Branch model**: create feature branches from `main`.
- **PR requirements**: Reference a GitHub issue, include tests,
  run `make format` and `make lint`, add a `semver:` label
  (`patch` | `minor` | `major`).
- **Pre-commit hooks**: MUST NOT be skipped (`--no-verify` is
  forbidden).
- **Starting LocalStack for local testing**: MUST use
  `python -m localstack.dev.run` from the project's `.venv`
  virtual environment. This ensures local code changes are
  mounted correctly into the Docker container. Do NOT use
  `localstack start` for development — it runs the pre-built
  image without local source changes.
- **Test execution**: `pytest <path/to/test_file.py>` or
  `pytest <path> -k <test_name>` for specific tests.
  Use `AWS_PROFILE=ls-sandbox TEST_TARGET=AWS_CLOUD
  SNAPSHOT_UPDATE=1 pytest <path>` for AWS validation.
- **Commit discipline**: Commit after each logical unit of
  work. Never force-push or rewrite published history.

## Governance

This constitution is the authoritative reference for
development practices in the LocalStack project. All code
reviews and pull requests MUST verify compliance with these
principles.

- **Amendments**: Any change to this constitution MUST be
  documented with a version bump, rationale, and migration
  plan for affected code.
- **Versioning**: This document follows semantic versioning.
  MAJOR for principle removals or incompatible redefinitions,
  MINOR for new principles or material expansions, PATCH for
  clarifications and typo fixes.
- **Compliance review**: Reviewers SHOULD use the Constitution
  Check section in plan documents to verify alignment before
  approving implementation plans.
- **Runtime guidance**: `AGENTS.md` is the primary operational
  reference for day-to-day development. This constitution
  governs architectural principles and the amendment process.
  Additional documentation lives in `docs/` in the repository
  root.

**Version**: 1.1.1 | **Ratified**: 2026-02-12 | **Last Amended**: 2026-02-13
