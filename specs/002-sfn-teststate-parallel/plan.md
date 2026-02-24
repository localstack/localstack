# Implementation Plan: StepFunctions TestState Parallel State Support

**Branch**: `002-sfn-teststate-parallel` | **Date**: 2026-02-24 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/002-sfn-teststate-parallel/spec.md`

## Summary

Add Parallel state support to the StepFunctions TestState API by extending the
existing mock/decorator architecture. This includes input validation (mock result
must be a JSON array matching branch count), a new `MockedStateParallel` class
for execution, and registration of `StateType.Parallel` as a supported test
state type. All behavior must match AWS as verified by snapshot tests run at
all inspection levels (INFO, DEBUG, TRACE).

## Technical Context

**Language/Version**: Python 3.11+
**Primary Dependencies**: antlr4 (ASL parsing), pytest, localstack testing framework
**Storage**: N/A (in-memory state during execution)
**Testing**: pytest with `@markers.aws.validated` and snapshot matching
**Target Platform**: Linux (Docker container)
**Project Type**: AWS emulator service
**Performance Goals**: N/A (correctness over performance)
**Constraints**: Must match AWS behavior exactly (snapshot parity)
**Scale/Scope**: ~5 files modified, ~3 new files created, ~10 new test cases

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Test-First (NON-NEGOTIABLE) | PASS | Tests will be written first and run against AWS before implementation |
| II. AWS Parity Testing | PASS | All tests use `@markers.aws.validated` with `SNAPSHOT_UPDATE=1` |
| III. Snapshot Integrity | PASS | Snapshots auto-generated from AWS runs, never edited manually |
| IV. LocalStack Verification (NON-NEGOTIABLE) | PASS | Implementation marked complete only after tests pass against LocalStack |
| V. Development Environment | PASS | `python -m localstack.dev.run` for LocalStack verification |
| VI. Resource Safety | PASS | Using existing fixtures, no hardcoded IDs, no auto-generated file edits |
| VII. Simplicity | PASS | Following existing MockedStateMap pattern, minimal new abstractions |

**Post-design re-check**: All gates still PASS. No new violations introduced.

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
│   ├── component/test_state/state/
│   │   ├── parallel.py                    # NEW: MockedStateParallel
│   │   ├── base_mock.py                   # existing (no changes)
│   │   ├── map.py                         # existing reference pattern
│   │   ├── task.py                        # existing reference pattern
│   │   └── common.py                      # existing reference pattern
│   ├── parse/test_state/
│   │   └── preprocessor.py                # MODIFY: register StateParallel in _decorate_state_field
│   └── static_analyser/test_state/
│       └── test_state_analyser.py         # MODIFY: add Parallel to _SUPPORTED_STATE_TYPES + validation
├── backend/test_state/
│   └── test_state_mock.py                 # MODIFY: handle Parallel mock result distribution (if needed)

tests/aws/services/stepfunctions/
├── v2/test_state/
│   └── test_state_mock_validation.py      # MODIFY: add Parallel validation tests
│   └── test_test_state_mock_scenarios.py  # MODIFY: add Parallel execution tests
├── templates/test_state/
│   ├── test_state_templates.py            # MODIFY: add Parallel template references
│   └── statemachines/
│       ├── base_parallel_state.json5      # NEW: base Parallel state template
│       └── io_parallel_state.json5        # NEW: Parallel with I/O processing fields
```

**Structure Decision**: Follows existing LocalStack project structure. All new
files are placed alongside their analogous Map state counterparts.

## Complexity Tracking

No constitution violations. No complexity justification needed.
