# Implementation Plan: StepFunctions TestState Parallel State Support

**Branch**: `002-sfn-teststate-parallel` | **Date**: 2026-02-24 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/002-sfn-teststate-parallel/spec.md`
**Constitution**: v1.1.0 (2026-02-24)

## Summary

Add Parallel state support to the StepFunctions TestState API in LocalStack.
This requires: (1) mock result validation — reject non-array mock results and
array size mismatches against branch count, (2) mock execution — create a
`MockedStateParallel` class following the `MockedStateMap` pattern, and (3)
parity tests — snapshot-verified tests at all inspection levels. The approach
extends the existing TestState mock/decorator architecture, adding Parallel as
a new entry alongside the existing Task, Map, and common state handlers.

## Technical Context

**Language/Version**: Python 3.11+ (runtime uses 3.13)
**Primary Dependencies**: antlr4-python3-runtime (ASL parsing), pytest, localstack-snapshot (snapshot testing), botocore
**Storage**: N/A (in-memory state processing)
**Testing**: pytest with `@markers.aws.validated`, `snapshot.match()`, `sfn_snapshot` fixture
**Target Platform**: Linux (Docker container) / macOS (dev)
**Project Type**: Cloud service emulator (AWS parity)
**Performance Goals**: N/A (API validation feature, follows existing TestState performance)
**Constraints**: Must match exact AWS error messages and response formats
**Scale/Scope**: ~5 source files modified/created, ~2 test files created, ~3 JSON5 templates

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| # | Principle | Gate | Status |
|---|-----------|------|--------|
| I | Test-First Development (NON-NEGOTIABLE) | Tests written before implementation; test tasks complete only when snapshots recorded from AWS; implementation tasks complete only when tests pass against LocalStack | PASS |
| II | AWS Parity Testing | All tests use `@markers.aws.validated`; snapshots recorded via `AWS_PROFILE=ls-sandbox TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 pytest <path> -v` | PASS |
| III | Snapshot Integrity | No manual snapshot edits; all assertions use `snapshot.match()`; snapshot transformers for non-deterministic values | PASS |
| IV | LocalStack Verification (NON-NEGOTIABLE) | Implementation not marked complete until tests pass against running LocalStack instance | PASS |
| V | Development Environment + Lifecycle (v1.1.0) | Use `python -m localstack.dev.run` from `.venv`; follow 5-step lifecycle: (1) verify stopped, (2) start, (3) verify running, (4) stop after tests, (5) verify stopped | PASS |
| VI | Resource Safety | Use fixtures for resource creation; use `account_id`/`region_name` fixtures; no `aws/api/` modifications; no dependency additions | PASS |
| VII | Simplicity | Follow existing `MockedStateMap` pattern; integration tests only; no new abstractions beyond what Map state already established | PASS |

**Hard Constraint Verification**:
- No manual snapshot edits planned
- All tests will use `snapshot.match()` (no plain `assert`)
- No AWS resources created directly in test bodies (using `aws_client_no_sync_prefix` fixture)
- No hardcoded account IDs or region names
- No `aws/api/` modifications
- No new dependencies
- No `git push` without approval

## Project Structure

### Documentation (this feature)

```text
specs/002-sfn-teststate-parallel/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
└── tasks.md             # Phase 2 output (/speckit.tasks)
```

### Source Code (repository root)

```text
localstack-core/localstack/services/stepfunctions/
├── asl/
│   ├── static_analyser/test_state/
│   │   └── test_state_analyser.py      # MODIFY: add Parallel to _SUPPORTED_STATE_TYPES,
│   │                                   #          add validate_mock_result_matches_parallel_definition()
│   ├── component/test_state/
│   │   ├── state/
│   │   │   └── parallel.py             # CREATE: MockedStateParallel
│   │   └── program/
│   │       └── test_state_program.py   # (no changes needed)
│   └── parse/test_state/
│       └── preprocessor.py             # MODIFY: add StateParallel to _decorate_state_field(),
│                                       #          extend find_state() for Parallel branches

tests/aws/services/stepfunctions/
├── v2/test_state/
│   └── test_state_mock_validation.py   # MODIFY: add Parallel state validation tests
│   └── test_test_state_mock_scenarios.py # MODIFY: add Parallel state execution tests
└── templates/test_state/
    ├── test_state_templates.py         # MODIFY: add Parallel template constants
    └── statemachines/
        ├── base_parallel_state.json5   # CREATE: minimal 2-branch Parallel state
        └── io_parallel_state.json5     # CREATE: Parallel state with I/O processing
```

**Structure Decision**: This feature modifies existing LocalStack service code
following the established TestState architecture. No new directories or modules
are needed beyond the single `parallel.py` file in the test_state/state/
directory, which follows the existing pattern (task.py, map.py, common.py).

## Complexity Tracking

> No Constitution Check violations. No complexity justifications needed.
