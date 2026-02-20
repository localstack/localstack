# Quickstart: StepFunctions TestState Parallel State Support

## Prerequisites

- LocalStack development environment set up (`make install`)
- AWS credentials configured for parity testing (`AWS_PROFILE=ls-sandbox`)

## Testing the feature

### 1. Run validation tests against AWS (to capture snapshots)

```bash
AWS_PROFILE=ls-sandbox TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 \
  pytest tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py \
  -k "parallel" -v
```

### 2. Run validation tests against LocalStack

```bash
pytest tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py \
  -k "parallel" -v
```

### 3. Run full TestState mock validation suite (regression check)

```bash
pytest tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py -v
```

## Manual verification

Use the AWS CLI against LocalStack to test manually:

```bash
# Test with invalid mock (non-array) — should return ValidationException
awslocal stepfunctions test-state \
  --definition '{
    "Type": "Parallel",
    "Branches": [
      {"StartAt": "B1", "States": {"B1": {"Type": "Pass", "End": true}}},
      {"StartAt": "B2", "States": {"B2": {"Type": "Pass", "End": true}}}
    ],
    "End": true
  }' \
  --mock '{"result": "{\"not\": \"an array\"}"}'

# Test with wrong array size — should return ValidationException
awslocal stepfunctions test-state \
  --definition '{
    "Type": "Parallel",
    "Branches": [
      {"StartAt": "B1", "States": {"B1": {"Type": "Pass", "End": true}}},
      {"StartAt": "B2", "States": {"B2": {"Type": "Pass", "End": true}}}
    ],
    "End": true
  }' \
  --mock '{"result": "[1]"}'

# Test with valid mock — should succeed
awslocal stepfunctions test-state \
  --definition '{
    "Type": "Parallel",
    "Branches": [
      {"StartAt": "B1", "States": {"B1": {"Type": "Pass", "End": true}}},
      {"StartAt": "B2", "States": {"B2": {"Type": "Pass", "End": true}}}
    ],
    "End": true
  }' \
  --mock '{"result": "[1, 2]"}'
```
