# Quickstart: Native IAM Provider Implementation

**Feature**: 001-iam-native-provider
**Date**: 2025-12-12

## Prerequisites

- Python 3.11+
- LocalStack development environment set up
- Familiarity with LocalStack Provider Pattern

## Development Setup

```bash
# Clone and setup LocalStack
cd localstack-core

# Install development dependencies
make install

# Run LocalStack locally
DEBUG=1 localstack start
```

## Implementation Order

### Phase 1: Core Infrastructure

1. **Create Store and Models**
   ```
   localstack-core/localstack/services/iam/
   ├── models.py          # New: Data models + IamStore
   └── provider.py        # Modify: Replace moto calls
   ```

2. **Implement Core Resources**
   - Users (CreateUser, GetUser, ListUsers, DeleteUser, UpdateUser)
   - Roles (CreateRole, GetRole, ListRoles, DeleteRole)
   - Groups (CreateGroup, GetGroup, ListGroups, DeleteGroup)
   - Policies (CreatePolicy, GetPolicy, ListPolicies, DeletePolicy)

### Phase 2: Credentials & Attachments

3. **Implement Access Keys**
   - CreateAccessKey, DeleteAccessKey, ListAccessKeys, UpdateAccessKey
   - GetAccessKeyLastUsed

4. **Implement Policy Operations**
   - Inline policies (Put, Get, Delete, List for User/Role/Group)
   - Managed policy attachments (Attach, Detach, List)
   - Policy versions (Create, Delete, Get, List, SetDefault)

### Phase 3: Advanced Features

5. **Implement Instance Profiles**
6. **Implement Service-Linked Roles**
7. **Implement Service-Specific Credentials**
8. **Implement MFA Devices**
9. **Implement Federation (OIDC/SAML)**
10. **Implement Account Operations**

## Key Code Patterns

### Store Access

```python
from localstack.services.iam.models import iam_stores, IamStore

def get_store(account_id: str, region: str) -> IamStore:
    return iam_stores[account_id][region]

# In handler:
store = self.get_store(context.account_id, context.region)
user = store.users.get(user_name)
```

### Handler Implementation

```python
from localstack.aws.api.iam import (
    IamApi,
    CreateUserRequest,
    CreateUserResponse,
    User,
    NoSuchEntityException,
    EntityAlreadyExistsException,
)

class IamProvider(IamApi, ServiceLifecycleHook):

    def create_user(
        self,
        context: RequestContext,
        user_name: str,
        path: str = "/",
        permission_boundary: str = None,
        tags: list = None,
    ) -> CreateUserResponse:
        store = self.get_store(context.account_id, context.region)

        # Validation
        if user_name in store.users:
            raise EntityAlreadyExistsException(
                f"User with name {user_name} already exists."
            )

        # Create user
        user_id = generate_user_id()
        arn = f"arn:aws:iam::{context.account_id}:user{path}{user_name}"

        user = User(
            user_name=user_name,
            user_id=user_id,
            arn=arn,
            path=path,
            create_date=datetime.utcnow(),
            permission_boundary=permission_boundary,
            tags=tags or [],
        )

        store.users[user_name] = user

        return CreateUserResponse(User=user)
```

### ID Generation

```python
from localstack.utils.strings import short_uid

def generate_user_id() -> str:
    return f"AIDA{short_uid().upper()[:16]}"

def generate_role_id() -> str:
    return f"AROA{short_uid().upper()[:16]}"

def generate_policy_id() -> str:
    return f"ANPA{short_uid().upper()[:16]}"
```

### Persistence

```python
from localstack.state import StateVisitor

class IamProvider(IamApi, ServiceLifecycleHook):

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(iam_stores)

    def on_after_state_load(self):
        # Rebuild any runtime caches after load
        pass
```

## Testing

### Run Existing Tests

```bash
# Run IAM tests against LocalStack
pytest tests/aws/services/iam/test_iam.py -v

# Run against AWS to update snapshots
TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 pytest tests/aws/services/iam/test_iam.py -v
```

### Add New Tests

```python
@markers.aws.validated
def test_create_user_basic(self, aws_client, snapshot, cleanups):
    snapshot.add_transformer(snapshot.transform.iam_api())

    user_name = f"test-user-{short_uid()}"

    response = aws_client.iam.create_user(UserName=user_name)
    cleanups.append(lambda: aws_client.iam.delete_user(UserName=user_name))

    snapshot.match("create-user", response)

    get_response = aws_client.iam.get_user(UserName=user_name)
    snapshot.match("get-user", get_response)
```

## Migration Checklist

- [x] Create `models.py` with all data models
- [x] Update `provider.py` to use `IamStore`
- [x] Remove moto imports one by one
- [x] Delete `iam_patches.py` when no longer needed (moved to STS)
- [x] Update STS integration
- [x] Update S3 presigned URL integration
- [x] Update CloudFormation resource providers
- [x] Run full test suite
- [x] Verify persistence works
- [x] Add AWS managed policies (1392 policies with lazy loading)

## Common Issues

### Issue: Tests failing with snapshot mismatches

**Solution**: Run against AWS to update snapshots:
```bash
TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 pytest <test_path>
```

### Issue: Cross-region data not shared

**Solution**: Use `CrossRegionAttribute` instead of `LocalAttribute` for IAM resources.

### Issue: Persistence not working

**Solution**: Ensure `accept_state_visitor` visits the store bundle:
```python
def accept_state_visitor(self, visitor: StateVisitor):
    visitor.visit(iam_stores)  # Must use the bundle, not individual stores
```

## Reference Files

- **S3 Provider**: `localstack/services/s3/provider.py`
- **Lambda Provider**: `localstack/services/lambda_/provider.py`
- **SNS Provider**: `localstack/services/sns/provider.py` (reference impl)
- **Existing IAM**: `localstack/services/iam/provider.py`
- **IAM API Types**: `localstack/aws/api/iam/__init__.py`
