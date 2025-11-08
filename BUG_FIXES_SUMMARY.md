# LocalStack Bug Fixes Summary

This document summarizes the bug fixes applied to the LocalStack codebase.

## Fixed Issues

### 1. ✅ Lambda Alias "Already Exists" Error on CDK Redeploy (#13351)

**Problem**: When using CDK with Lambda versions, redeploying would fail with "Alias already exists" error even though the alias configuration was identical.

**Solution**: Made `create_alias()` idempotent by:
- Checking if existing alias has identical configuration (version, description, routing)
- Returning existing alias without error if configuration matches (common in CDK redeployments)
- Only raising `ResourceConflictException` if configuration actually differs

**Files Modified**:
- `localstack-core/localstack/services/lambda_/provider.py`

**Behavior**:
- **Before**: CDK redeploy → "Alias already exists" error
- **After**: CDK redeploy → Success (idempotent operation)

---

### 2. ✅ StepFunctions InvalidArn Error Messages (#13315)

**Problem**: InvalidArn exceptions in StepFunctions didn't communicate which part of the ARN was incorrect, making debugging difficult.

**Solution**: Enhanced ARN validation methods to provide detailed error messages:
- `_validate_state_machine_arn()` - Now reports specific issues (missing parts, wrong service, wrong resource type)
- `_validate_state_machine_execution_arn()` - Validates execution ARNs with detailed feedback
- `_validate_activity_arn()` - Validates activity ARNs including name length constraints

**Files Modified**:
- `localstack-core/localstack/services/stepfunctions/provider.py`

**Example Error Messages**:
- Before: `Invalid arn: 'arn:aws:lambda:us-east-1:123456789012:function:test'`
- After: `Invalid arn: 'arn:aws:lambda:us-east-1:123456789012:function:test' - Service must be 'states', got 'lambda'`

---

### 3. ✅ Firehose S3 CompressionFormat Not Respected (#13301)

**Problem**: Kinesis Firehose was ignoring the `CompressionFormat` parameter when writing to S3, always storing data uncompressed.

**Solution**: Implemented compression support in `_put_records_to_s3_bucket()`:
- **GZIP** compression with automatic `.gz` extension
- **ZIP** compression with automatic `.zip` extension  
- **Snappy** compression with automatic `.snappy` extension (requires python-snappy)
- **UNCOMPRESSED** (default behavior)

**Files Modified**:
- `localstack-core/localstack/services/firehose/provider.py`

**Features Added**:
- Automatic file extension appending based on compression format
- Graceful fallback if Snappy library is not installed
- Warning logs for unknown compression formats

---

### 4. ✅ TestState Variables Not Interpolated (#13215)

**Problem**: The `variables` parameter in the `TestState` API was accepted but completely ignored, preventing variable interpolation in state definitions.

**Solution**: Implemented full variable support chain:
1. Added `variables` field to `TestStateExecution` class
2. Updated `TestStateExecutionWorker` to initialize `VariableStore` with provided variables
3. Modified `TestStateEnvironment` to accept and use `variable_store` parameter
4. Updated `test_state()` provider method to parse and pass variables to execution

**Files Modified**:
- `localstack-core/localstack/services/stepfunctions/provider.py`
- `localstack-core/localstack/services/stepfunctions/backend/test_state/execution.py`
- `localstack-core/localstack/services/stepfunctions/backend/test_state/execution_worker.py`
- `localstack-core/localstack/services/stepfunctions/asl/eval/test_state/environment.py`

**Usage Example**:
```python
# Variables can now be used in TestState
variables = '{"myVar": "myValue", "count": 42}'
result = sfn_client.test_state(
    definition=state_definition,
    roleArn=role_arn,
    input='{}',
    variables=variables
)
```

---

## Testing Recommendations

### Lambda Alias Redeploy (#13351)
```bash
# Create a Lambda function with version and alias
aws lambda create-function \
  --function-name test-function \
  --runtime python3.9 \
  --role arn:aws:iam::000000000000:role/lambda-role \
  --handler index.handler \
  --zip-file fileb://function.zip \
  --endpoint-url http://localhost:4566

# Publish version
aws lambda publish-version \
  --function-name test-function \
  --endpoint-url http://localhost:4566

# Create alias
aws lambda create-alias \
  --function-name test-function \
  --name prod \
  --function-version 1 \
  --endpoint-url http://localhost:4566

# Redeploy (create same alias again) - should succeed now
aws lambda create-alias \
  --function-name test-function \
  --name prod \
  --function-version 1 \
  --endpoint-url http://localhost:4566
```

### StepFunctions InvalidArn (#13315)
```bash
# Test with invalid ARNs
aws stepfunctions describe-state-machine \
  --state-machine-arn "arn:aws:lambda:us-east-1:123456789012:function:test" \
  --endpoint-url http://localhost:4566
```

### Firehose CompressionFormat (#13301)
```bash
# Create a Firehose stream with GZIP compression
aws firehose create-delivery-stream \
  --delivery-stream-name test-stream \
  --extended-s3-destination-configuration '{
    "BucketARN": "arn:aws:s3:::my-bucket",
    "CompressionFormat": "GZIP",
    "RoleARN": "arn:aws:iam::000000000000:role/firehose-role"
  }' \
  --endpoint-url http://localhost:4566

# Put records and verify they are compressed in S3
aws firehose put-record \
  --delivery-stream-name test-stream \
  --record '{"Data":"dGVzdCBkYXRh"}' \
  --endpoint-url http://localhost:4566
```

### TestState Variables (#13215)
```bash
# Test with variables
aws stepfunctions test-state \
  --definition '{"Type":"Pass","Result.$":"$.myVar"}' \
  --role-arn "arn:aws:iam::000000000000:role/test" \
  --input '{}' \
  --variables '{"myVar":"Hello World"}' \
  --endpoint-url http://localhost:4566
```

---

## Summary Statistics

- **Total Bugs Fixed**: 4
- **Files Modified**: 7
- **Services Improved**: Lambda, StepFunctions, Firehose

## Additional Notes

- All fixes maintain backward compatibility
- Error messages are now more AWS-compliant  
- Code follows existing LocalStack patterns and conventions
- No breaking changes to public APIs
- Idempotent operations now properly supported

## Remaining Issues (Not Fixed)

The following issues were identified but not fixed in this session:
- **#13316**: AppConfig GetLatestConfiguration endpoint behavior
- **#13278**: SSM GetParametersByPath validation (likely handled by moto)
- **#13319**: DynamoDB TransactWriteItems/TransactGetItems ARN support (requires moto changes)

These issues may require deeper investigation into service-specific implementations or external dependencies (moto).
