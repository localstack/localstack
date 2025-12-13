# LocalStack Codebase Study

A comprehensive study of the LocalStack codebase structure and service implementation patterns.

---

## Table of Contents

1. [Overview](#overview)
2. [Project Structure](#project-structure)
3. [Services Directory](#services-directory)
4. [AWS API Auto-Generation](#aws-api-auto-generation)
5. [Service Implementation Patterns](#service-implementation-patterns)
6. [State Management: AccountRegionBundle Pattern](#state-management-accountregionbundle-pattern)
7. [The @handler Decorator](#the-handler-decorator)
8. [Moto Integration](#moto-integration)
9. [Service Lifecycle Hooks](#service-lifecycle-hooks)
10. [Request Flow End-to-End](#request-flow-end-to-end)
11. [Testing Framework](#testing-framework)
12. [Key Takeaways](#key-takeaways)

---

## Overview

LocalStack is a fully functional local AWS cloud stack that emulates AWS services (S3, Lambda, DynamoDB, etc.) for development and testing. It runs in Docker, provides AWS-like APIs locally, enabling offline workflows, integration testing, and CI without calling real AWS endpoints.

This document covers the **open-source community edition** (`localstack-core`).

---

## Project Structure

### Root Level

```
localstack/
├── localstack-core/              # Core Python package (main implementation)
├── tests/                        # Test suite (unit, integration, AWS tests)
├── bin/                          # Shell scripts and CLI entry points
├── docs/                         # Documentation
├── scripts/                      # Utility scripts
├── .github/                      # GitHub workflows and CI/CD
├── .venv/                        # Python virtual environment
├── pyproject.toml               # Project configuration
├── Dockerfile                   # Container configuration
├── docker-compose.yml           # Local development setup
└── README.md, LICENSE.txt       # Project metadata
```

### Core Package Structure

**Path**: `localstack-core/localstack/`

```
localstack-core/localstack/
│
├── config.py                 # Configuration management (66KB)
├── constants.py              # Constants and environment variables
├── version.py               # Version information
├── plugins.py               # Plugin system for OpenAPI specs
│
├── aws/                      # AWS API and service integration
│   ├── api/                 # Auto-generated AWS API definitions (42 services)
│   ├── handlers/            # Request/response handlers
│   ├── protocol/            # Protocol implementations (JSON, XML, Query, REST)
│   ├── serving/             # Service routing and request serving
│   └── skeleton.py          # Handler discovery and dispatch
│
├── services/                 # AWS Service implementations (49 services)
│   ├── <service>/           # Each service folder contains:
│   │   ├── provider.py      # API handlers (extends generated API stub)
│   │   ├── models.py        # State stores (AccountRegionBundle pattern)
│   │   └── resource_providers/  # CloudFormation integration
│
├── runtime/                  # LocalStack runtime components
│   ├── init.py             # Initialization
│   ├── runtime.py          # Runtime management
│   ├── hooks.py            # Lifecycle hooks
│   └── server/             # HTTP server (Hypercorn, ASGI)
│
├── state/                    # State management and persistence
│   ├── core.py             # Core state handling
│   ├── pickle.py           # Serialization
│   └── snapshot.py         # State snapshots
│
├── testing/                  # Test infrastructure and fixtures
│   ├── pytest/             # Pytest plugins
│   └── snapshots/          # Snapshot testing
│
└── utils/                    # Utility modules (56 modules)
    ├── aws/                # AWS utility functions
    ├── files.py            # File operations
    ├── strings.py          # String utilities (short_uid, etc.)
    └── ...
```

---

## Services Directory

Located at `localstack-core/localstack/services/`

### Complete Service List (49 Services)

| Service | Description |
|---------|-------------|
| acm | AWS Certificate Manager |
| apigateway | API Gateway (legacy + next_gen) |
| cdk | CDK integration |
| cloudformation | CloudFormation engine |
| cloudwatch | CloudWatch |
| configservice | Config Service |
| dynamodb | DynamoDB (v2 implementation) |
| dynamodbstreams | DynamoDB Streams |
| ec2 | EC2 |
| ecr | Elastic Container Registry |
| es | Elasticsearch |
| events | EventBridge |
| firehose | Kinesis Firehose |
| iam | Identity and Access Management |
| kinesis | Kinesis |
| kms | Key Management Service |
| lambda_ | Lambda (with event source mapping) |
| logs | CloudWatch Logs |
| opensearch | OpenSearch |
| redshift | Redshift |
| resource_groups | Resource Groups |
| resourcegroupstaggingapi | Tagging API |
| route53 | Route 53 |
| route53resolver | Route 53 Resolver |
| s3 | S3 (storage, notifications, presigned_url) |
| s3control | S3 Control |
| scheduler | EventBridge Scheduler |
| secretsmanager | Secrets Manager |
| ses | Simple Email Service |
| sns | SNS (v2 implementation) |
| sqs | SQS |
| ssm | Systems Manager |
| stepfunctions | Step Functions (ASL, backend, mocking) |
| sts | Security Token Service |
| support | Support |
| swf | Simple Workflow Service |
| transcribe | Transcribe |

### Service Structure Pattern

Each service typically contains:

```
services/<service>/
├── __init__.py           # Service definition
├── provider.py           # Main service provider (API implementation)
├── models.py             # Data models and state stores
├── exceptions.py         # Service-specific exceptions
└── resource_providers/   # CloudFormation resource providers
```

---

## AWS API Auto-Generation

Located at `localstack-core/localstack/aws/api/`

### Overview

AWS APIs are auto-generated from AWS Smithy/botocore specifications. These files contain:
- Type definitions (TypedDict classes)
- Request/response models
- Exception classes
- Service interface (abstract base class)

**Important**: Files in `aws/api/` should **NEVER** be manually edited.

### Generating API Stubs

```bash
python -m localstack.aws.scaffold generate <service> --save [--doc]
```

### Example: SNS API Types

```python
# From localstack/aws/api/sns/__init__.py

class TopicAttributesMap(TypedDict, total=False):
    DeliveryPolicy: Optional[str]
    DisplayName: Optional[str]
    Policy: Optional[str]
    # ... more attributes

class CreateTopicInput(TypedDict, total=False):
    Name: str
    Attributes: Optional[TopicAttributesMap]
    Tags: Optional[TagList]
    DataProtectionPolicy: Optional[attributeValue]

class SnsApi:
    """Auto-generated service interface"""

    @handler("CreateTopic")
    def create_topic(
        self,
        context: RequestContext,
        name: topicName,
        attributes: TopicAttributesMap = None,
        tags: TagList = None,
        data_protection_policy: attributeValue = None,
        **kwargs,
    ) -> CreateTopicResponse:
        raise NotImplementedError
```

---

## Service Implementation Patterns

### Reference Implementation: SNS

The SNS service is the reference implementation for understanding LocalStack patterns.

**Files:**
- Provider: `localstack-core/localstack/services/sns/provider.py`
- Models: `localstack-core/localstack/services/sns/models.py`

### Provider Class Structure

```python
class SnsProvider(SnsApi, ServiceLifecycleHook):
    """
    Provider class for AWS Simple Notification Service.

    Inherits from:
    - SnsApi: Auto-generated API interface from botocore
    - ServiceLifecycleHook: Enables service lifecycle management
    """

    def __init__(self) -> None:
        super().__init__()
        self._publisher = PublishDispatcher()
        self._signature_cert_pem: str = SNS_SERVER_CERT

    # ServiceLifecycleHook methods
    def on_before_stop(self):
        self._publisher.shutdown()

    def on_after_init(self):
        register_sns_api_resource(ROUTER)
        ROUTER.add(self.get_signature_cert_pem_file)
```

### Handler Method Pattern

```python
def publish(
    self,
    context: RequestContext,
    message: String,
    topic_arn: topicARN = None,
    target_arn: String = None,
    phone_number: String = None,
    subject: String = None,
    message_structure: messageStructure = None,
    message_attributes: MessageAttributeMap = None,
    message_deduplication_id: String = None,
    message_group_id: String = None,
    **kwargs,
) -> PublishResponse:
    # 1. Validation
    if subject == "":
        raise InvalidParameterException("Invalid parameter: Subject")
    if not message or all(not m for m in message):
        raise InvalidParameterException("Invalid parameter: Empty message")

    # 2. Parse ARN and get store
    parsed_arn = parse_and_validate_topic_arn(topic_or_target_arn)
    store = self.get_store(
        account_id=parsed_arn["account"],
        region_name=context.region
    )

    # 3. Create message context
    message_ctx = SnsMessage(
        type=SnsMessageType.Notification,
        message=message,
        message_attributes=message_attributes,
        # ... more fields
    )

    # 4. Dispatch
    publish_ctx = SnsPublishContext(
        message=message_ctx,
        store=store,
        request_headers=context.request.headers
    )
    self._publisher.publish_to_topic(publish_ctx, topic_or_target_arn)

    return PublishResponse(MessageId=message_ctx.message_id)
```

### Key Conventions

| Convention | Description |
|------------|-------------|
| **Types** | Import from `localstack.aws.api.<service>` |
| **Errors** | Use service-specific exceptions or `CommonServiceException` |
| **IDs** | Use `short_uid()` from `localstack.utils.strings` |
| **ARNs** | Use helpers from `localstack.utils.aws.arns` |
| **Logging** | `LOG = logging.getLogger(__name__)` at module top |
| **Stores** | Use `AccountRegionBundle` pattern |

---

## State Management: AccountRegionBundle Pattern

### Overview

LocalStack uses a descriptor-based pattern to manage state at different scopes:
- **LocalAttribute**: Region-specific (default)
- **CrossRegionAttribute**: Shared across regions within an account
- **CrossAccountAttribute**: Shared across all accounts

### Store Definition

```python
# From localstack/services/sns/models.py

class SnsStore(BaseStore):
    # LocalAttribute: Region-specific storage
    topic_subscriptions: dict[str, list[str]] = LocalAttribute(default=dict)
    subscriptions: dict[str, SnsSubscription] = LocalAttribute(default=dict)
    subscription_tokens: dict[str, str] = LocalAttribute(default=dict)
    sns_tags: dict[str, list[dict]] = LocalAttribute(default=dict)
    platform_endpoint_messages: dict[str, list[dict]] = LocalAttribute(default=dict)
    sms_messages: list[dict] = LocalAttribute(default=list)

    # Helper methods
    def get_topic_subscriptions(self, topic_arn: str) -> list[SnsSubscription]:
        topic_subscriptions = self.topic_subscriptions.get(topic_arn, [])
        return [
            subscription
            for subscription_arn in topic_subscriptions
            if (subscription := self.subscriptions.get(subscription_arn))
        ]

# Global store singleton
sns_stores = AccountRegionBundle("sns", SnsStore)
```

### Hierarchy

```
AccountRegionBundle["account_id"]  →  RegionBundle
RegionBundle["region_name"]        →  Store (e.g., SnsStore)
```

### Access Pattern

```python
# Navigate through the hierarchy
account_id = '001122334455'
region_name = 'us-east-1'

store = sns_stores[account_id][region_name]  # Returns SnsStore instance
topics = store.topic_subscriptions           # dict[str, list[str]]

# Each store maintains reference to its context
store._account_id      # "001122334455"
store._region_name     # "us-east-1"
store._service_name    # "sns"
```

### How Descriptors Work

**LocalAttribute** uses Python's descriptor protocol:

```python
class LocalAttribute:
    def __set_name__(self, owner, name):
        self.name = LOCAL_ATTR_PREFIX + name  # "attr_topic_subscriptions"

    def __get__(self, obj, objtype=None):
        if not hasattr(obj, self.name):
            if isinstance(self.default, Callable):
                value = self.default()  # Call dict, list, etc.
            else:
                value = self.default
            setattr(obj, self.name, value)
        return getattr(obj, self.name)
```

When you access `store.topic_subscriptions`, it lazily initializes the dict for that store instance.

---

## The @handler Decorator

### Definition

```python
# From localstack/aws/api/core.py

def handler(
    operation: str | None = None,
    context: bool = True,
    expand: bool = True
) -> Callable:
    """
    Decorator that marks a method as an operation handler.

    Args:
        operation: AWS operation name (e.g., "CreateTopic")
        context: Whether to pass RequestContext to handler
        expand: Whether to expand request parameters as kwargs
    """
    def wrapper(fn):
        @functools.wraps(fn)
        def operation_marker(*args, **kwargs):
            return fn(*args, **kwargs)

        # Store metadata on the wrapper
        operation_marker.operation = operation
        operation_marker.expand_parameters = expand
        operation_marker.pass_context = context

        return operation_marker
    return wrapper
```

### Handler Discovery (Skeleton)

```python
# From localstack/aws/skeleton.py

def create_dispatch_table(delegate: object) -> DispatchTable:
    """
    Scan the provider class tree for @handler-marked methods.
    """
    cls_tree = inspect.getmro(delegate.__class__)
    handlers: dict[str, HandlerAttributes] = {}

    for cls in reversed(list(cls_tree)):
        for name, fn in inspect.getmembers(cls, inspect.isfunction):
            try:
                handlers[fn.operation] = HandlerAttributes(
                    fn.__name__,
                    fn.operation,
                    fn.pass_context,
                    fn.expand_parameters
                )
            except AttributeError:
                pass  # Not a handler method

    # Create dispatcher for each handler
    dispatch_table: DispatchTable = {}
    for handler in handlers.values():
        bound_function = getattr(delegate, handler.function_name)
        dispatch_table[handler.operation] = ServiceRequestDispatcher(
            bound_function,
            operation=handler.operation,
            pass_context=handler.pass_context,
            expand_parameters=handler.expand_parameters,
        )

    return dispatch_table
```

---

## Moto Integration

LocalStack uses [Moto](https://github.com/spulec/moto) as a backend for many services.

### Direct Call

```python
from localstack.services.moto import call_moto

def get_topic_attributes(
    self, context: RequestContext, topic_arn: topicARN, **kwargs
) -> GetTopicAttributesResponse:
    # Validate topic exists
    moto_topic_model = self._get_topic(topic_arn, context)

    # Delegate to moto
    moto_response: GetTopicAttributesResponse = call_moto(context)

    # Post-process moto response if needed
    attributes = moto_response["Attributes"]
    for attr in vars(moto_topic_model):
        if "_feedback" in attr:
            key = camelcase_to_pascal(underscores_to_camelcase(attr))
            attributes[key] = getattr(moto_topic_model, attr)

    return moto_response
```

### Fallback Pattern

```python
from localstack.services.moto import MotoFallbackDispatcher

# Wraps provider with moto fallthrough
# If provider raises NotImplementedError, moto handles it
dispatch_table = MotoFallbackDispatcher(provider)
```

### Direct Backend Access

```python
from moto.sns import sns_backends

@staticmethod
def get_moto_backend(account_id: str, region_name: str) -> SNSBackend:
    return sns_backends[account_id][region_name]

# Usage
moto_topic = self.get_moto_backend(account_id, region).topics[arn]
```

---

## Service Lifecycle Hooks

```python
class ServiceLifecycleHook(StateLifecycleHook):
    def on_after_init(self):
        """Called after service is initialized - set up routes, etc."""
        pass

    def on_before_start(self):
        """Called before service starts - prepare resources"""
        pass

    def on_before_stop(self):
        """Called before service stops - cleanup, shutdown threads"""
        pass

    def on_exception(self):
        """Called when service encounters an error"""
        pass
```

### Example Usage in SNS

```python
class SnsProvider(SnsApi, ServiceLifecycleHook):
    def on_after_init(self):
        # Register custom HTTP endpoints
        register_sns_api_resource(ROUTER)
        ROUTER.add(self.get_signature_cert_pem_file)

    def on_before_stop(self):
        # Graceful shutdown
        self._publisher.shutdown()
```

---

## Request Flow End-to-End

```
1. HTTP Request arrives
   ↓
2. RequestContext created
   - Parses headers for account_id, region, auth
   - Service name determined
   ↓
3. Skeleton created for service
   - Scans provider for @handler methods
   - Builds dispatch table (operation → handler)
   ↓
4. Operation discovered from request
   - Parsed to RequestContext.operation
   - ServiceRequest dict created from body/query
   ↓
5. Handler invoked
   ├─ Handler method called with context + expanded parameters
   ├─ Accesses store via sns_stores[account_id][region_name]
   ├─ Performs validation and business logic
   ├─ Returns response or raises ServiceException
   ↓
6. Response serialized
   - If ServiceException: error serialized
   - If NotImplementedError: fall through to moto or return 501
   ↓
7. HTTP Response sent
```

---

## Testing Framework

### Test Directory Structure

```
tests/
├── unit/                        # Unit tests
│   ├── aws/                    # AWS-related unit tests
│   ├── services/               # Service unit tests
│   └── utils/                  # Utility function tests
│
├── integration/                 # Integration tests
│   ├── services/               # Service integration tests
│   └── templates/              # CloudFormation tests
│
├── aws/                        # AWS parity tests
│   ├── services/              # Per-service tests (20+ services)
│   │   ├── sns/
│   │   ├── sqs/
│   │   ├── s3/
│   │   └── ...
│   └── templates/             # CloudFormation templates
│
└── conftest.py                # Pytest configuration
```

### Test Patterns

```python
@markers.aws.validated
def test_create_topic_with_attributes(self, sns_create_topic, snapshot, aws_client):
    # Custom transformers for dynamic values
    snapshot.add_transformer(snapshot.transform.sns_api())

    # Use fixtures for resource creation
    create_topic = sns_create_topic(
        Name="topictest.fifo",
        Attributes={"FifoTopic": "true"},
    )
    topic_arn = create_topic["TopicArn"]

    # Match response against snapshot
    get_attrs_resp = aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
    snapshot.match("get-topic-attrs", get_attrs_resp)

    # Test error cases
    with pytest.raises(ClientError) as e:
        aws_client.sns.get_topic_attributes(TopicArn="invalid-arn")
    snapshot.match("get-attrs-error", e.value.response)
```

### Key Fixtures

| Fixture | Description |
|---------|-------------|
| `aws_client` | Boto3 clients (`aws_client.s3`, `aws_client.lambda_`) |
| `snapshot` | Snapshot matching and transformers |
| `account_id` | Current account ID (never hardcode) |
| `region_name` | Current region (never hardcode) |
| `deploy_cfn_template` | Deploy CloudFormation with lifecycle |
| `cleanups` | Register cleanup code for teardown |

### Running Tests

```bash
# Run test file
pytest <path/to/test_file.py>

# Run specific test
pytest <path/to/test_file.py> -k <test_name>

# Run against AWS to record snapshots
TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 pytest <path>
```

---

## Key Takeaways

1. **Provider Pattern**: Services inherit from auto-generated API interfaces and implement operations as methods

2. **Descriptor-Based State**: Python descriptors (LocalAttribute, CrossRegionAttribute, CrossAccountAttribute) provide elegant multi-account/multi-region state management

3. **Store Hierarchy**: `AccountRegionBundle` → `RegionBundle` → `Store` provides clean isolation while sharing state where needed

4. **Handler Discovery**: Reflection-based discovery scans class hierarchy for @handler-marked methods

5. **Moto Integration**: Both direct calls and fallback mechanism for unimplemented features

6. **Lifecycle Management**: ServiceLifecycleHook allows graceful initialization and shutdown

7. **Request Context**: Central RequestContext carries request metadata through the handler chain

8. **Validation First**: Comprehensive validation before business logic with AWS-compliant errors

9. **Cross-Account/Region**: ARN-based access allows operations across accounts/regions

10. **Snapshot Testing**: Tests run against real AWS and snapshots ensure LocalStack parity

---

## Commands Reference

```bash
# Development setup
make install           # Install dependencies with venv
make entrypoints       # Regenerate plugin entry points
make start             # Start LocalStack in host mode

# Testing
pytest <path/to/test_file.py>                # Run test file
pytest <path> -k <test_name>                  # Run specific test
TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 pytest <path>  # Record snapshots

# Code quality
make lint              # Lint check
make format            # Format all

# API generation
python -m localstack.aws.scaffold generate <service> --save [--doc]
```

---

## Critical Constraints

**NEVER:**
- Modify `*.snapshot.json` or `*.validation.json` files manually
- Use plain `assert` in validated tests — use `snapshot.match()`
- Create AWS resources directly in test bodies — use fixtures
- Hardcode account IDs or region names
- Modify files in `localstack-core/localstack/aws/api/` — auto-generated
- Add new project dependencies without approval

---

## References

- **Testing Docs:** `docs/testing/README.md`
- **Architecture:** `docs/localstack-concepts/README.md`
- **Contributing:** `docs/CONTRIBUTING.md`
- **Common Fixtures:** `localstack-core/localstack/testing/pytest/fixtures.py`
- **Test Markers:** `localstack-core/localstack/testing/pytest/marking.py`
