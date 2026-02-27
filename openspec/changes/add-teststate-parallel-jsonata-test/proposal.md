## Why

The Step Functions TestState API supports Parallel states with JSONPath I/O processing (InputPath, ResultPath, OutputPath), but there is no test coverage for Parallel states using JSONata query language. JSONata uses a different I/O model (`Arguments`/`Output` instead of `InputPath`/`Parameters`/`ResultPath`/`OutputPath`), and we need AWS-validated snapshot tests to ensure LocalStack handles this correctly.

## What Changes

- Add a new JSONata Parallel state template (`io_jsonata_parallel_state.json5`) using `QueryLanguage: "JSONata"` with `Arguments` and `Output` fields
- Add a new test `test_io_jsonata_parallel_state_mock_success` that exercises the template with mock data across INFO, DEBUG, and TRACE inspection levels
- Record AWS snapshots for the new test to establish ground truth
- Fix any LocalStack implementation gaps if the test fails against LocalStack

## Capabilities

### New Capabilities
- `teststate-parallel-jsonata`: Test coverage for TestState API handling of Parallel states with JSONata query language and I/O processing

### Modified Capabilities

## Impact

- **Test files**: `tests/aws/services/stepfunctions/v2/test_state/test_test_state_mock_scenarios.py` — new test method
- **Templates**: `tests/aws/services/stepfunctions/templates/test_state/statemachines/io_jsonata_parallel_state.json5` — new template file
- **Template registry**: `tests/aws/services/stepfunctions/templates/test_state/test_state_templates.py` — new template constant
- **Snapshots**: `tests/aws/services/stepfunctions/v2/test_state/test_test_state_mock_scenarios.snapshot.json` — updated with new entries
- **Provider**: `localstack/services/stepfunctions/` — potential implementation fixes if test fails against LocalStack
