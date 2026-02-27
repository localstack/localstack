## 1. Template and Registry

- [x] 1.1 Create `tests/aws/services/stepfunctions/templates/test_state/statemachines/io_jsonata_parallel_state.json5` — a Parallel state with `"QueryLanguage": "JSONata"`, `"Arguments"` to select `parallelInput` from input, `"Output"` to shape the result, and two branches (B1, B2) each with a Pass state
- [x] 1.2 Add `IO_JSONATA_PARALLEL_STATE` constant to `TestStateTemplate` class in `tests/aws/services/stepfunctions/templates/test_state/test_state_templates.py` pointing to the new template file

## 2. Test

- [x] 2.1 Add `test_io_jsonata_parallel_state_mock_success` method to `TestStateMockScenarios` class in `tests/aws/services/stepfunctions/v2/test_state/test_test_state_mock_scenarios.py` — parametrized over `INSPECTION_LEVELS` (INFO, DEBUG, TRACE), using the new template, input `{"parallelInput": {"data": "input_value"}}`, mock result `[{"branch1": "result"}, {"branch2": "result"}]`, with `snapshot.match()` assertion

## 3. AWS Snapshot Recording

- [x] 3.1 Run the new test against AWS with `AWS_PROFILE=ls-sandbox TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 pytest tests/aws/services/stepfunctions/v2/test_state/test_test_state_mock_scenarios.py::TestStateMockScenarios::test_io_jsonata_parallel_state_mock_success -v` and verify snapshot files are created/updated on disk

## 4. LocalStack Verification

- [x] 4.1 Verify LocalStack is stopped (`localstack status`), start with `python -m localstack.dev.run`, verify running (`localstack status`)
- [x] 4.2 Run the test against LocalStack: `pytest tests/aws/services/stepfunctions/v2/test_state/test_test_state_mock_scenarios.py::TestStateMockScenarios::test_io_jsonata_parallel_state_mock_success -v`
- [x] 4.3 If the test fails, investigate and fix the Step Functions provider implementation until all three inspection level variants pass
- [x] 4.4 Stop LocalStack (`localstack stop`) and verify stopped (`localstack status`)
