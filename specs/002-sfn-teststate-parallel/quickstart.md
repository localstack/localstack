# Quickstart: StepFunctions TestState Parallel State Support

## Verify the Feature

### 1. Start LocalStack with local changes

```bash
python -m localstack.dev.run
```

### 2. Test validation: mock result is not an array

```bash
aws stepfunctions test-state \
  --endpoint-url http://localhost:4566 \
  --definition '{
    "Type": "Parallel",
    "Branches": [
      {"StartAt": "B1", "States": {"B1": {"Type": "Pass", "End": true}}},
      {"StartAt": "B2", "States": {"B2": {"Type": "Pass", "End": true}}}
    ],
    "End": true
  }' \
  --mock '{"result": "{\"key\": \"value\"}"}' \
  --inspection-level TRACE
```

Expected: `ValidationException` — mock result must be a JSON array for
Parallel states.

### 3. Test validation: mock result array size mismatch

```bash
aws stepfunctions test-state \
  --endpoint-url http://localhost:4566 \
  --definition '{
    "Type": "Parallel",
    "Branches": [
      {"StartAt": "B1", "States": {"B1": {"Type": "Pass", "End": true}}},
      {"StartAt": "B2", "States": {"B2": {"Type": "Pass", "End": true}}}
    ],
    "End": true
  }' \
  --mock '{"result": "[{\"branch1\": \"result\"}]"}' \
  --inspection-level TRACE
```

Expected: `ValidationException` — mock result array size (1) does not match
branch count (2).

### 4. Test successful execution

```bash
aws stepfunctions test-state \
  --endpoint-url http://localhost:4566 \
  --definition '{
    "Type": "Parallel",
    "Branches": [
      {"StartAt": "B1", "States": {"B1": {"Type": "Pass", "End": true}}},
      {"StartAt": "B2", "States": {"B2": {"Type": "Pass", "End": true}}}
    ],
    "End": true
  }' \
  --mock '{"result": "[{\"branch1\": \"result\"}, {\"branch2\": \"result\"}]"}' \
  --inspection-level TRACE
```

Expected: Successful execution with output containing both branch results.

## Run Tests

```bash
# Run against AWS to record snapshots
AWS_PROFILE=ls-sandbox TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 \
  pytest tests/aws/services/stepfunctions/v2/test_state/ -v -k "parallel"

# Run against LocalStack
pytest tests/aws/services/stepfunctions/v2/test_state/ -v -k "parallel"
```
