## ADDED Requirements

### Requirement: JSONata Parallel state template exists
A JSON5 template file SHALL define a Parallel state with `"QueryLanguage": "JSONata"`, `"Arguments"` for input transformation, and `"Output"` for result shaping. The template SHALL have two branches (B1 and B2) each containing a Pass state, matching the structure of `io_parallel_state.json5`.

#### Scenario: Template is loadable
- **WHEN** the template file `io_jsonata_parallel_state.json5` is loaded via `TestStateTemplate`
- **THEN** it SHALL return a valid JSON object with `"Type": "Parallel"`, `"QueryLanguage": "JSONata"`, `"Arguments"`, `"Output"`, and two `"Branches"`

### Requirement: Template registered in TestStateTemplate
The `TestStateTemplate` class SHALL expose a constant `IO_JSONATA_PARALLEL_STATE` pointing to the new template file.

#### Scenario: Template constant resolves to file
- **WHEN** `TST.IO_JSONATA_PARALLEL_STATE` is accessed
- **THEN** it SHALL resolve to `statemachines/io_jsonata_parallel_state.json5` under the test_state templates directory

### Requirement: TestState API returns correct response for JSONata Parallel state with mock
The TestState API SHALL accept a JSONata Parallel state definition with a mock result and return a response that includes the output shaped by the `Output` JSONata expression. The response SHALL be validated via snapshot matching against AWS-recorded ground truth.

#### Scenario: Mock success at INFO inspection level
- **WHEN** `test_state` is called with the JSONata Parallel template, input `{"parallelInput": {"data": "input_value"}}`, mock result `[{"branch1": "result"}, {"branch2": "result"}]`, and `inspectionLevel=INFO`
- **THEN** the response SHALL match the AWS-recorded snapshot for INFO level

#### Scenario: Mock success at DEBUG inspection level
- **WHEN** `test_state` is called with the same parameters but `inspectionLevel=DEBUG`
- **THEN** the response SHALL match the AWS-recorded snapshot for DEBUG level

#### Scenario: Mock success at TRACE inspection level
- **WHEN** `test_state` is called with the same parameters but `inspectionLevel=TRACE`
- **THEN** the response SHALL match the AWS-recorded snapshot for TRACE level

### Requirement: Test passes against LocalStack
The test SHALL pass against a running LocalStack instance with local code mounted. If the test fails, the Step Functions provider implementation SHALL be fixed until the test passes.

#### Scenario: LocalStack parity
- **WHEN** the test is run against LocalStack via `pytest <path> -v` (no `TEST_TARGET`)
- **THEN** all snapshot matches SHALL pass, confirming parity with AWS behavior
