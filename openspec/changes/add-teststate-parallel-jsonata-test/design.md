## Context

The TestState API allows testing individual Step Functions states without creating a full state machine. Existing tests cover Parallel states with JSONPath-based I/O processing (`InputPath`, `ResultPath`, `OutputPath`). JSONata is an alternative query language supported by Step Functions that replaces these fields with `Arguments` (input transformation) and `Output` (output transformation) using `{% ... %}` expression syntax. No test currently validates Parallel state + JSONata through the TestState API.

The existing test `test_io_parallel_state_mock_success` provides the pattern: it uses `TST.IO_PARALLEL_STATE` (a template with `InputPath`/`ResultPath`/`OutputPath`), mocks branch results, and snapshots the response across all three inspection levels.

## Goals / Non-Goals

**Goals:**
- Add a JSONata Parallel state template that uses `Arguments` and `Output` instead of JSONPath I/O fields
- Add a parametrized test mirroring `test_io_parallel_state_mock_success` for the JSONata variant
- Record AWS snapshots as ground truth
- Ensure the test passes against LocalStack, fixing implementation if needed

**Non-Goals:**
- Testing JSONata expression evaluation edge cases (covered elsewhere)
- Testing Parallel state error handling with JSONata (separate concern)
- Adding JSONata variants for non-Parallel test state templates

## Decisions

**1. Template structure: top-level `QueryLanguage: "JSONata"` with `Arguments`/`Output`**

The JSONata template will set `"QueryLanguage": "JSONata"` at the state level and use `"Arguments"` to select input and `"Output"` to shape the result. This mirrors the pattern used in existing JSONata templates under `templates/statevariables/` and `templates/querylanguage/`.

Alternative: Per-branch JSONata override. Rejected because the goal is to test the Parallel state's own I/O processing, not branch-level query language mixing.

**2. Template file naming: `io_jsonata_parallel_state.json5`**

Follows the existing `io_` prefix convention (e.g., `io_parallel_state.json5`, `io_pass_state.json5`) indicating I/O processing is configured, with `jsonata` inserted to distinguish from the JSONPath variant.

**3. Test parametrization: reuse existing `INSPECTION_LEVELS` list**

The test will use `@pytest.mark.parametrize("inspection_level", INSPECTION_LEVELS)` identical to the existing parallel tests, covering INFO, DEBUG, and TRACE levels.

**4. Mock data: same structure as existing parallel test**

Use the same mock result shape (`[{"branch1": "result"}, {"branch2": "result"}]`) to keep the test focused on JSONata I/O processing differences rather than branch result content.

## Risks / Trade-offs

- **[Risk] LocalStack may not support JSONata I/O for Parallel states in TestState** → The test will reveal this gap. If the test fails against LocalStack, we fix the provider implementation as part of this change.
- **[Risk] Template JSONata expressions could differ from AWS expectations** → Mitigated by recording real AWS snapshots first, establishing ground truth before LocalStack verification.
