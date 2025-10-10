<!--
SYNC IMPACT REPORT
==================
Version Change: Template (unversioned) → 1.0.0
Initial Constitution: First ratification for AWS Ground Station service implementation

Added Sections:
- Core Principles (5 principles: AWS API Compatibility, Code Quality, Testing Standards,
  Documentation, Performance & Security)
- Technical Constraints
- Development Workflow
- Governance

Modified Principles: N/A (initial version)
Removed Sections: N/A (initial version)

Template Consistency Status:
- ✅ .specify/templates/plan-template.md - Constitution Check section aligned
- ✅ .specify/templates/spec-template.md - Requirements alignment verified
- ✅ .specify/templates/tasks-template.md - Task categorization compatible
- ⚠️  .specify/templates/commands/*.md - No command files found, validation skipped

Follow-up TODOs: None
-->

# LocalStack AWS Ground Station Service Constitution

## Core Principles

### I. AWS API Compatibility (NON-NEGOTIABLE)

Implementation MUST match AWS Ground Station API specifications exactly as defined in botocore.
All request parameters, response structures, error codes, and behavior MUST align with AWS
documentation and actual AWS Ground Station service behavior. Deviations are only permitted
when explicitly documented as implementation limitations.

**Rationale**: LocalStack's primary value proposition is AWS compatibility, enabling developers
to test their AWS applications locally without modification. Breaking API compatibility defeats
this core purpose.

### II. Code Quality & ASF Framework Adherence

All code MUST:
- Use LocalStack's ASF (AWS Service Framework) for service implementation
- Follow LocalStack's plugin architecture and service registration patterns
- Adhere to Python style guide (PEP 8) and LocalStack's coding conventions
- Include type hints throughout all code
- Use LocalStack's import conventions and logging utilities
- Handle exceptions with AWS-compatible error codes
- Follow LocalStack's state management system (AccountRegionBundle and BaseStore)

**Rationale**: Consistency with LocalStack's architecture ensures maintainability, reduces
technical debt, and allows the Ground Station service to integrate seamlessly with existing
LocalStack features like persistence, Cloud Pods, and multi-account support.

### III. Testing Standards (NON-NEGOTIABLE)

Testing MUST achieve:
- Minimum 80% test coverage across all implemented functionality
- Both unit tests and integration tests for each API operation
- Test coverage for error conditions and edge cases
- Use of @markers.aws.validated for AWS parity tests
- Proper use of pytest fixtures and LocalStack's test markers
- Tests MUST follow LocalStack's 14 rules for stable tests (R01-R14)

**Rationale**: LocalStack's stability depends on comprehensive testing. The 14 established
testing rules prevent flaky tests, ensure idempotency, and maintain pipeline reliability.
Ground Station service must meet these standards to avoid degrading overall project quality.

### IV. Documentation & Clarity

All code MUST include:
- Comprehensive docstrings for all public methods and classes
- Inline comments for non-obvious logic
- User-facing service documentation
- Clear documentation of any AWS Ground Station limitations
- Service implementation level classification (CRUD vs Emulated)

**Rationale**: LocalStack serves a diverse user base. Clear documentation reduces support
burden, accelerates contributor onboarding, and helps users understand service capabilities
and limitations.

### V. Performance & Security

Implementation MUST:
- Respond to CRUD operations in under 100ms
- Validate all input parameters according to AWS specifications
- Enforce proper ARN format validation
- Return ResourceNotFound errors when appropriate
- Return parameter validation errors with descriptive messages
- Support LocalStack's IAM integration for permission validation
- Remain purely emulated (no real satellite connections)

**Rationale**: Performance consistency maintains LocalStack's developer experience. Security
validation prevents undefined behavior and ensures AWS-compatible error handling, which is
critical for testing error scenarios.

## Technical Constraints

All Ground Station service implementation MUST:
- Use LocalStack's ASF framework - no alternative frameworks permitted
- Integrate with LocalStack's multi-account and multi-region architecture
- Support LocalStack's persistence mechanism
- Support Cloud Pods features
- Generate and validate ARNs following AWS patterns
- Avoid external dependencies beyond LocalStack's existing stack
- Use existing LocalStack services (S3, Lambda, etc.) as reference implementations

## Development Workflow

### Implementation Levels

Follow progressive implementation approach:
1. **CRUD Level**: Basic create, read, update, delete operations with proper request/response
   handling
2. **Emulated Level**: Business logic, state transitions, validations, realistic behavior

Each level MUST be:
- Clearly documented in code comments and service documentation
- Tested at minimum 80% coverage before progressing to next level
- Reviewed for AWS compatibility

### Code Standards

- Commit messages MUST follow Conventional Commits format
- Follow semver labeling for PRs: patch (small fixes), minor (features), major (breaking)
- Run `make format` and `make lint` before committing
- All PRs MUST increase or maintain test coverage

### Quality Gates

Before merging:
- All tests passing (unit and integration)
- Coverage threshold met (≥80%)
- Linting passes without errors
- Documentation complete
- AWS parity validated where applicable

## Governance

This constitution supersedes all other development practices for the AWS Ground Station
service implementation.

### Amendment Procedure

Amendments require:
1. Documented rationale for the change
2. Impact analysis on existing implementation
3. Updated version number following semantic versioning
4. Synchronization of all dependent template files
5. Review and approval from LocalStack maintainers

### Compliance Review

All pull requests MUST:
- Verify compliance with constitutional principles
- Document any principle deviations with explicit justification
- Align with LocalStack's contribution guidelines
- Not break existing LocalStack features
- Maintain backwards compatibility with LocalStack configuration

### Constitutional Violations

Complexity that violates principles MUST be justified in implementation plan's Complexity
Tracking section. If no justification can be provided, simplify the approach.

### Non-Negotiable Principles

Principles marked (NON-NEGOTIABLE) cannot be bypassed under any circumstances. These represent
LocalStack's core architectural and quality commitments.

**Version**: 1.0.0 | **Ratified**: 2025-10-03 | **Last Amended**: 2025-10-03