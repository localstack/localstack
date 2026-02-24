# Quickstart: StepFunctions TestState Parallel State Support

## Development Workflow (Constitution v1.1.0)

### Step 1: Write tests and record AWS snapshots

```bash
# Run tests against real AWS to record snapshots
AWS_PROFILE=ls-sandbox TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 \
  pytest tests/aws/services/stepfunctions/v2/test_state/ -v -k "parallel"

# Verify snapshot files were created/updated
ls tests/aws/services/stepfunctions/v2/test_state/*.snapshot.json
```

### Step 2: Implement the feature

Modify files per the plan's Source Code section.

### Step 3: Verify against LocalStack (5-step lifecycle)

```bash
# (1) Verify stopped before starting
localstack status
# Confirm runtime status is "stopped". If running, stop first:
# localstack stop && localstack status

# (2) Start LocalStack with local changes
python -m localstack.dev.run

# (3) Verify running
localstack status
# Confirm runtime status is "running" before proceeding

# (4) Run tests against LocalStack
pytest tests/aws/services/stepfunctions/v2/test_state/ -v -k "parallel"

# (5) Stop LocalStack and verify stopped
localstack stop
localstack status
# Confirm runtime status is "stopped" before proceeding
```

## Manual Verification Examples

### Test validation: mock result is not an array

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

### Test validation: mock result array size mismatch

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

### Test successful execution

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

## Run All Tests

```bash
# Against AWS (record snapshots)
AWS_PROFILE=ls-sandbox TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 \
  pytest tests/aws/services/stepfunctions/v2/test_state/ -v -k "parallel"

# Against LocalStack (verify implementation)
pytest tests/aws/services/stepfunctions/v2/test_state/ -v -k "parallel"

# Regression: ensure existing tests still pass
pytest tests/aws/services/stepfunctions/v2/test_state/ -v
```
