## ADDED Requirements

### Requirement: Parallel state mock result must be a JSON array
When the TestState API receives a definition containing a Parallel state with a mock result, the system SHALL validate that the mock result is a valid JSON array. If the mock result is not a JSON array (e.g., a JSON object, string, number, or boolean), the system SHALL reject the request with a `ValidationException`.

#### Scenario: Mock result is a JSON object instead of array
- **WHEN** a TestState request is made with a Parallel state definition and `mock.result` is a JSON object (e.g., `{"key": "value"}`)
- **THEN** the system SHALL raise a `ValidationException` indicating the mocked result must be an array

#### Scenario: Mock result is a JSON string instead of array
- **WHEN** a TestState request is made with a Parallel state definition and `mock.result` is a JSON string (e.g., `"hello"`)
- **THEN** the system SHALL raise a `ValidationException` indicating the mocked result must be an array

### Requirement: Parallel state mock result array length must match branch count
When the TestState API receives a definition containing a Parallel state with a mock result that is a valid JSON array, the system SHALL validate that the array length equals the number of branches defined in the Parallel state. If the lengths do not match, the system SHALL reject the request with a `ValidationException`.

#### Scenario: Mock result array has fewer elements than branches
- **WHEN** a TestState request is made with a Parallel state definition that has 3 branches and `mock.result` is a JSON array with 2 elements
- **THEN** the system SHALL raise a `ValidationException` indicating the mocked result size does not match the number of branches

#### Scenario: Mock result array has more elements than branches
- **WHEN** a TestState request is made with a Parallel state definition that has 2 branches and `mock.result` is a JSON array with 3 elements
- **THEN** the system SHALL raise a `ValidationException` indicating the mocked result size does not match the number of branches

### Requirement: Parallel state without mock raises InvalidDefinition
When the TestState API receives a definition containing a Parallel state without a mock configuration, the system SHALL reject the request with an `InvalidDefinition` error, consistent with existing behavior for Map states without mocks.

#### Scenario: Parallel state with no mock
- **WHEN** a TestState request is made with a Parallel state definition and no `mock` parameter
- **THEN** the system SHALL raise an `InvalidDefinition` error stating that TestState API does not support Parallel states without mocks
