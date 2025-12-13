# Research: Native IAM Provider

**Feature**: 001-iam-native-provider
**Date**: 2025-12-12

## Technical Decisions

### 1. State Management Pattern

**Decision**: Use `AccountRegionBundle` with `CrossRegionAttribute` for IAM resources

**Rationale**:
- IAM is a global service in AWS (not region-specific)
- LocalStack's `CrossRegionAttribute` provides account-wide data sharing
- Pattern is proven in S3, Lambda, and other native services
- Enables proper multi-account isolation while maintaining global semantics

**Alternatives Considered**:
- LocalAttribute: Rejected because IAM resources are global per account, not per region
- CrossAccountAttribute: Rejected because IAM resources must be isolated per account

### 2. Store Structure

**Decision**: Single `IamStore` class with categorized attributes

**Rationale**:
- All IAM resources belong to a single logical namespace
- Single store simplifies persistence and state management
- Follows patterns from S3 (`s3_stores`) and Lambda (`lambda_stores`)

**Structure**:
```python
class IamStore(BaseStore):
    # Principal resources (CrossRegionAttribute - global per account)
    users: dict[str, User] = CrossRegionAttribute(default=dict)
    groups: dict[str, Group] = CrossRegionAttribute(default=dict)
    roles: dict[str, Role] = CrossRegionAttribute(default=dict)
    instance_profiles: dict[str, InstanceProfile] = CrossRegionAttribute(default=dict)

    # Policies
    policies: dict[str, ManagedPolicy] = CrossRegionAttribute(default=dict)
    aws_managed_policies: dict[str, AWSManagedPolicy] = CrossAccountAttribute(default=dict)

    # Identity providers
    saml_providers: dict[str, SAMLProvider] = CrossRegionAttribute(default=dict)
    oidc_providers: dict[str, OIDCProvider] = CrossRegionAttribute(default=dict)

    # Credentials (keyed by user ARN/name)
    access_keys: dict[str, AccessKey] = CrossRegionAttribute(default=dict)

    # MFA
    virtual_mfa_devices: dict[str, VirtualMFADevice] = CrossRegionAttribute(default=dict)

    # Certificates
    server_certificates: dict[str, ServerCertificate] = CrossRegionAttribute(default=dict)
    signing_certificates: dict[str, SigningCertificate] = CrossRegionAttribute(default=dict)

    # Account settings
    account_aliases: list[str] = CrossRegionAttribute(default=list)
    password_policy: PasswordPolicy = CrossRegionAttribute(default=None)
    account_summary: AccountSummary = CrossRegionAttribute(default=None)

    # Tags (cross-account for shared implementation)
    TAGS: TaggingService = CrossAccountAttribute(default=TaggingService)

iam_stores = AccountRegionBundle("iam", IamStore)
```

### 3. Model Classes

**Decision**: Use dataclasses for all IAM resource models

**Rationale**:
- Consistent with LocalStack patterns (Lambda, S3)
- Dataclasses provide clean serialization for persistence
- Type hints improve code quality and IDE support

**Key Models**:
- `User`: username, user_id, arn, path, create_date, permission_boundary, tags, groups, inline_policies, attached_policies, login_profile, mfa_devices, access_keys, service_specific_credentials, ssh_public_keys
- `Role`: role_name, role_id, arn, path, assume_role_policy_document, create_date, description, max_session_duration, permission_boundary, tags, inline_policies, attached_policies, last_used
- `Group`: group_name, group_id, arn, path, create_date, users, inline_policies, attached_policies
- `ManagedPolicy`: policy_name, policy_id, arn, path, create_date, versions (list), default_version_id, attachment_count, is_attachable, description, tags
- `PolicyVersion`: version_id, document, is_default_version, create_date
- `InstanceProfile`: instance_profile_name, instance_profile_id, arn, path, create_date, roles (list), tags
- `AccessKey`: access_key_id, secret_access_key, status, create_date, user_name, last_used_date, last_used_service, last_used_region

### 4. AWS Managed Policies Loading

**Decision**: Lazy-load from embedded JSON data file

**Rationale**:
- ~3.5MB of policy data is too large to initialize on every request
- Lazy loading improves startup time
- JSON file can be updated independently
- Follows moto's approach for AWS managed policies

**Implementation**:
- Store policy definitions in `localstack/services/iam/aws_managed_policies.json`
- Load into `CrossAccountAttribute` on first access
- Cache in memory after initial load

### 5. Service-Linked Role Definitions

**Decision**: Maintain definitions in Python dict, migrate from existing implementation

**Rationale**:
- Current implementation already defines 60+ service-linked roles
- Python dict provides type safety and easy lookup
- Definitions rarely change, don't need external file

**Source**: Migrate from `localstack-core/localstack/services/iam/provider.py` (existing `SERVICE_LINKED_ROLES` dict)

### 6. ID Generation

**Decision**: Generate AWS-compatible IDs using prefix + random alphanumeric

**Rationale**:
- AWS uses predictable prefixes (AIDA for users, AROA for roles, etc.)
- LocalStack should match these patterns for compatibility
- Use `short_uid()` utility for random portion

**ID Formats**:
| Resource | Prefix | Example |
|----------|--------|---------|
| User | AIDA | AIDAEXAMPLE123456 |
| Role | AROA | AROAEXAMPLE123456 |
| Group | AGPA | AGPAEXAMPLE123456 |
| Policy | ANPA | ANPAEXAMPLE123456 |
| Instance Profile | AIPA | AIPAEXAMPLE123456 |
| Access Key | AKIA (or LKIA for LocalStack) | AKIAEXAMPLE123456 |
| Server Cert | ASCA | ASCAEXAMPLE123456 |

### 7. Persistence Integration

**Decision**: Use standard `accept_state_visitor` pattern

**Rationale**:
- Consistent with all other LocalStack services
- No file-based assets for IAM (unlike S3)
- Automatic serialization/deserialization of store

**Implementation**:
```python
def accept_state_visitor(self, visitor: StateVisitor):
    visitor.visit(iam_stores)
```

### 8. Error Handling

**Decision**: Use generated exception classes from `localstack.aws.api.iam`

**Rationale**:
- Auto-generated exceptions match AWS error codes exactly
- Consistent with Provider Pattern principle
- Type-safe and IDE-friendly

**Key Exceptions**:
- `NoSuchEntityException` - Resource not found
- `EntityAlreadyExistsException` - Duplicate resource
- `DeleteConflictException` - Resource has dependencies
- `InvalidInputException` - Invalid parameter value
- `LimitExceededException` - Quota exceeded
- `MalformedPolicyDocumentException` - Invalid policy JSON
- `ServiceNotSupportedException` - Unsupported operation

### 9. Testing Strategy

**Decision**: AWS-validated snapshot testing with existing fixtures

**Rationale**:
- Constitution requires `@markers.aws.validated` tests
- Existing fixtures (`create_user`, `create_role`, `create_policy`) should be reused
- Snapshot testing ensures AWS parity

**Approach**:
- Add new tests to existing `tests/aws/services/iam/test_iam.py`
- Use `snapshot.transform.iam_api()` for dynamic value masking
- Target 95%+ AWS validation coverage

### 10. Migration Strategy

**Decision**: Incremental replacement with compatibility layer

**Rationale**:
- Big-bang replacement is too risky
- Need to maintain backward compatibility during transition
- Allows testing each component independently

**Phases**:
1. Create store and models alongside existing moto integration
2. Implement core operations (users, roles, groups, policies)
3. Implement credentials (access keys, MFA, service-specific)
4. Implement federation (OIDC, SAML)
5. Implement account operations (alias, password policy, reports)
6. Remove moto imports and patches

## Dependencies

### Required LocalStack Modules

| Module | Purpose |
|--------|---------|
| `localstack.services.stores` | AccountRegionBundle, BaseStore, attributes |
| `localstack.services.plugins` | ServiceLifecycleHook |
| `localstack.aws.api.iam` | Generated API types and exceptions |
| `localstack.utils.tagging` | TaggingService |
| `localstack.utils.strings` | short_uid() for ID generation |
| `localstack.utils.aws.arns` | ARN construction utilities |
| `localstack.state` | StateVisitor for persistence |

### No External Dependencies

The native IAM implementation should not require any new external dependencies. All functionality will be built using:
- Standard Python library (dataclasses, datetime, json, re)
- Existing LocalStack utilities
- Generated AWS API types

## Integration Points

### STS Integration

**Current**: STS already uses IAM backend for `AssumeRole`
**Change**: Update STS to use new `iam_stores` instead of moto backends

**Files to Update**:
- `localstack/services/sts/provider.py` - Update IAM backend access

### S3 Presigned URLs

**Current**: S3 validates access keys against moto's IAM backend
**Change**: Update to use `iam_stores.access_keys`

**Files to Update**:
- `localstack/services/s3/presigned_url.py` - Update access key lookup

### CloudFormation

**Current**: IAM resource providers delegate to moto
**Change**: Update to call native provider methods

**Files to Update**:
- `localstack/services/iam/resource_providers/*.py` - Update all providers

## Open Questions (Resolved)

1. **Q: Should access keys use "AKIA" or "LKIA" prefix?**
   - A: Use configurable behavior (PARITY_AWS_ACCESS_KEY_ID flag exists)

2. **Q: How to handle AWS managed policies updates?**
   - A: Periodically update JSON file from AWS documentation

3. **Q: Should policy simulation actually evaluate policies?**
   - A: Basic implementation for FR-019; full evaluation engine is out of scope
