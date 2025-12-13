<!--
╔══════════════════════════════════════════════════════════════════════════════╗
║                           SYNC IMPACT REPORT                                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Version Change: N/A → 1.0.0 (initial creation)                               ║
║                                                                              ║
║ Modified Principles: N/A (initial)                                           ║
║                                                                              ║
║ Added Sections:                                                              ║
║   - Core Principles (I through X)                                            ║
║   - Critical Constraints                                                      ║
║   - Development Workflow                                                      ║
║   - Governance                                                               ║
║                                                                              ║
║ Removed Sections: N/A (initial)                                              ║
║                                                                              ║
║ Templates Status:                                                            ║
║   - .specify/templates/plan-template.md      ✅ Compatible (Constitution     ║
║     Check section aligns with principles)                                    ║
║   - .specify/templates/spec-template.md      ✅ Compatible (Requirements     ║
║     and testing sections align with Parity Testing principle)                ║
║   - .specify/templates/tasks-template.md     ✅ Compatible (Phase structure  ║
║     and test-first approach align with principles)                           ║
║                                                                              ║
║ Follow-up TODOs: None                                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
-->

# LocalStack Constitution

LocalStack is a fully functional local AWS cloud stack that emulates AWS services
(S3, Lambda, DynamoDB, etc.) for development and testing. This constitution
establishes the non-negotiable principles governing all contributions to the
open-source community edition (`localstack-core`).

## Core Principles

### I. Provider Pattern

Every AWS service implementation MUST follow the Provider Pattern:

- Service providers MUST inherit from auto-generated API interfaces in
  `localstack.aws.api.<service>`
- Providers MUST implement `ServiceLifecycleHook` for lifecycle management
- Handler methods MUST accept `RequestContext` as the first parameter
- All operations MUST be discoverable via the `@handler` decorator mechanism

**Rationale**: Uniform provider structure enables consistent request routing,
handler discovery via reflection, and predictable service behavior across all
49+ AWS service implementations.

### II. State Management (AccountRegionBundle)

All service state MUST use the AccountRegionBundle pattern:

- State stores MUST extend `BaseStore` from `localstack.services.stores`
- Region-scoped data MUST use `LocalAttribute` descriptors
- Cross-region data MUST use `CrossRegionAttribute` descriptors
- Cross-account data MUST use `CrossAccountAttribute` descriptors
- Store access MUST follow: `stores[account_id][region_name]`

**Rationale**: Descriptor-based state management provides clean multi-account
and multi-region isolation while enabling controlled state sharing where AWS
semantics require it.

### III. API Auto-Generation (DO NOT EDIT)

Files in `localstack-core/localstack/aws/api/` MUST NEVER be manually edited:

- API types are auto-generated from AWS Smithy/botocore specifications
- TypedDict classes, request/response models, and exceptions are generated
- Service interfaces (abstract base classes) define the handler contract
- Regenerate using: `python -m localstack.aws.scaffold generate <service> --save`

**Rationale**: Auto-generated APIs ensure type safety and AWS specification
compliance. Manual edits would be overwritten and create drift from AWS behavior.

### IV. Moto Integration

LocalStack MUST leverage Moto appropriately for backend functionality:

- Use `call_moto(context)` to delegate operations to moto implementations
- Use `MotoFallbackDispatcher` to wrap providers for unimplemented operations
- Access moto backends directly via `from moto.<service> import <service>_backends`
- Post-process moto responses when LocalStack requires additional attributes

**Rationale**: Moto provides battle-tested AWS mock implementations. Leveraging
moto reduces duplication and accelerates feature coverage while maintaining
parity with AWS behavior.

### V. Parity Testing (NON-NEGOTIABLE)

All AWS service tests MUST validate against real AWS:

- Use `@markers.aws.validated` for tests that run against AWS
- NEVER modify `*.snapshot.json` or `*.validation.json` files manually
- ALWAYS use `snapshot.match()` instead of plain `assert` in validated tests
- Add transformers BEFORE `snapshot.match()` for non-deterministic values
- Record snapshots with: `TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 pytest <path>`

**Rationale**: Snapshot testing against real AWS ensures LocalStack maintains
behavioral parity. Manual snapshot edits bypass validation and introduce drift.

### VI. Fixture-Based Resource Management

AWS resources in tests MUST be created via fixtures:

- NEVER create AWS resources directly in test bodies
- ALWAYS use factory fixtures (e.g., `sns_create_topic`, `s3_create_bucket`)
- Fixtures MUST return entire response from create operations
- Fixtures MUST store only names/ARNs in cleanup lists
- Fixtures MUST use `yield` for automatic cleanup after test completion
- Log cleanup errors with `LOG.debug()` for debugging with `-s`

**Rationale**: Fixture-based resource management ensures proper cleanup,
prevents resource leaks, and enables test isolation and parallelization.

### VII. Dynamic Value Handling

Tests MUST NOT hardcode account IDs or region names:

- ALWAYS use `account_id` fixture for AWS account numbers
- ALWAYS use `region_name` fixture for AWS regions
- Use `short_uid()` from `localstack.utils.strings` for randomized IDs
- Tests MUST be idempotent and parallelizable

**Rationale**: Hardcoded values break multi-account support and prevent
parallel test execution. Randomized IDs ensure test isolation.

### VIII. Service Lifecycle Hooks

Services MUST implement lifecycle hooks for proper resource management:

- `on_after_init()`: Register routes, initialize components
- `on_before_start()`: Prepare resources before service starts
- `on_before_stop()`: Cleanup, shutdown threads, release resources
- `on_exception()`: Handle service errors gracefully

**Rationale**: Lifecycle hooks enable graceful initialization and shutdown,
preventing resource leaks and ensuring clean state transitions.

### IX. Error Handling

Services MUST use AWS-compliant error handling:

- Use service-specific exceptions from `localstack.aws.api.<service>`
- Fall back to `CommonServiceException` for generic errors
- Validate inputs before business logic execution
- Error messages MUST match AWS error response format

**Rationale**: AWS-compliant errors ensure client applications (SDKs, CLI)
behave identically against LocalStack and real AWS.

### X. Code Conventions

All code MUST follow LocalStack conventions:

- Import types from `localstack.aws.api.<service>`
- Use `LOG = logging.getLogger(__name__)` at module top
- Use helpers from `localstack.utils.aws.arns` for ARN operations
- Use `short_uid()` for ID generation
- Follow the SNS service as the reference implementation

**Rationale**: Consistent conventions reduce cognitive load, ease code review,
and enable effective codebase navigation.

## Critical Constraints

The following actions are strictly prohibited:

| Constraint | Violation Impact |
|------------|------------------|
| Modify `*.snapshot.json` manually | Breaks AWS parity validation |
| Modify `*.validation.json` manually | Corrupts test baselines |
| Edit files in `aws/api/` | Overwrites on regeneration |
| Use plain `assert` in validated tests | Bypasses snapshot comparison |
| Create resources in test bodies | Causes resource leaks |
| Hardcode account IDs/regions | Breaks multi-account support |
| Add dependencies without approval | Bloats container image |
| Run `git push` or modify history | Disrupts collaboration |
| Use `time.sleep()` in tests | Creates flaky tests |

## Development Workflow

### Implementing New Operations

1. **Write a failing test first** — Capture AWS behavior with
   `TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1`
2. **Find the provider** — Look in `localstack-core/localstack/services/<service>/provider.py`
3. **Check the store** — State issues often in `models.py`
4. **Compare with AWS docs** — Verify expected behavior
5. **Run test against LocalStack** — Ensure snapshot matches
6. **Iterate** — Run tests individually, see failures, fix, re-run

### Code Quality Gates

```bash
make lint              # Lint check (MUST pass)
make format            # Format all code
pytest <path>          # Run tests
```

### Test Stability Rules

| Rule | Description |
|------|-------------|
| R01 | Mark flaky tests with `@pytest.mark.skip(reason="flaky")` |
| R06 | Use `poll_condition()` instead of `time.sleep()` |
| R08 | Ensure features work with arbitrary account numbers |
| R09 | Use randomized IDs (`short_uid()`) for idempotency |
| R10 | Use transformers for deterministic snapshots |
| R13 | Always clean up resources via fixture teardown |
| R14 | Use appropriate fixture scopes |

## Governance

This constitution supersedes all other development practices for LocalStack.
Amendments require:

1. **Documentation**: Clear description of proposed change and rationale
2. **Review**: Approval from project maintainers
3. **Migration Plan**: Strategy for updating existing code if needed
4. **Version Bump**: Following semantic versioning:
   - MAJOR: Backward-incompatible principle changes
   - MINOR: New principles or expanded guidance
   - PATCH: Clarifications and wording fixes

### Compliance

- All PRs MUST verify compliance with these principles
- Complexity beyond these principles MUST be explicitly justified
- Use `AGENTS.md` for runtime development guidance

### References

- **Testing Docs**: `docs/testing/README.md`
- **Architecture**: `docs/localstack-concepts/README.md`
- **Contributing**: `docs/CONTRIBUTING.md`
- **Common Fixtures**: `localstack-core/localstack/testing/pytest/fixtures.py`
- **Reference Implementation**: SNS service (`localstack/services/sns/`)

**Version**: 1.0.0 | **Ratified**: 2025-12-12 | **Last Amended**: 2025-12-12
