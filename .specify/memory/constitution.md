<!--
  Sync Impact Report
  ═══════════════════════════════════════════════
  Version change: N/A → 1.0.0 (initial ratification)
  Modified principles: N/A (initial creation)
  Added sections:
    - Core Principles (5 principles)
    - Technical Constraints
    - Development Workflow
    - Governance
  Removed sections: N/A
  Templates requiring updates:
    - .specify/templates/plan-template.md ✅ no updates needed
      (Constitution Check section already generic)
    - .specify/templates/spec-template.md ✅ no updates needed
      (User stories, requirements, and success criteria align)
    - .specify/templates/tasks-template.md ✅ no updates needed
      (Phase structure and testing conventions align)
    - .specify/templates/commands/ — no command files exist yet
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

## Development Workflow

- **Branch model**: Fork the repository; create feature
  branches from `main`.
- **PR requirements**: Reference a GitHub issue, include tests,
  run `make format` and `make lint`, add a `semver:` label
  (`patch` | `minor` | `major`).
- **Pre-commit hooks**: MUST NOT be skipped (`--no-verify` is
  forbidden).
- **Test execution**: `TEST_PATH="tests/aws/services/<svc>"
  make test` or direct pytest invocation with `-k` filter.
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
- **Runtime guidance**: For detailed implementation guidance,
  refer to `AGENTS.md` and `docs/` in the repository root.

**Version**: 1.0.0 | **Ratified**: 2026-02-12 | **Last Amended**: 2026-02-12
