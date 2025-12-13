# Data Model: Native IAM Provider

**Feature**: 001-iam-native-provider
**Date**: 2025-12-12

## Entity Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         IAM Store                                │
│  (AccountRegionBundle - one per AWS account)                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐                   │
│  │   User   │◄──►│  Group   │    │   Role   │                   │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘                   │
│       │               │               │                          │
│       │ has           │ has           │ has                      │
│       ▼               ▼               ▼                          │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐                   │
│  │AccessKey │    │ Inline   │    │ Instance │                   │
│  │MFA Device│    │ Policy   │    │ Profile  │                   │
│  │LoginProf │    │ Attached │    │          │                   │
│  └──────────┘    │ Policy   │    └──────────┘                   │
│                  └──────────┘                                    │
│                                                                  │
│  ┌──────────────────────────────────────────┐                   │
│  │           Managed Policies               │                   │
│  │  ┌─────────────┐    ┌─────────────┐      │                   │
│  │  │   Custom    │    │     AWS     │      │                   │
│  │  │   Policy    │    │   Managed   │      │                   │
│  │  └─────────────┘    └─────────────┘      │                   │
│  └──────────────────────────────────────────┘                   │
│                                                                  │
│  ┌──────────────────────────────────────────┐                   │
│  │         Identity Providers               │                   │
│  │  ┌─────────────┐    ┌─────────────┐      │                   │
│  │  │    SAML     │    │    OIDC     │      │                   │
│  │  │  Provider   │    │  Provider   │      │                   │
│  │  └─────────────┘    └─────────────┘      │                   │
│  └──────────────────────────────────────────┘                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Core Entities

### User

IAM user identity that can authenticate and be assigned permissions.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| user_name | str | Unique name within account | 1-64 chars, `[\w+=,.@-]+` |
| user_id | str | Unique identifier | AIDA + 16 alphanumeric |
| arn | str | Amazon Resource Name | `arn:aws:iam::{account}:user/{path}{name}` |
| path | str | Organizational path | Default "/" |
| create_date | datetime | Creation timestamp | UTC |
| permission_boundary | str | Policy ARN for boundary | Optional |
| tags | dict[str, str] | Resource tags | Max 50 tags |
| groups | list[str] | Group names user belongs to | |
| inline_policies | dict[str, str] | Policy name → document | |
| attached_policies | list[str] | Attached policy ARNs | Max 10 |
| login_profile | LoginProfile | Console access profile | Optional |
| mfa_devices | list[str] | MFA device serial numbers | Max 8 |
| access_keys | list[str] | Access key IDs | Max 2 |
| service_specific_credentials | list[str] | Credential IDs | |
| ssh_public_keys | list[str] | SSH key IDs | |
| signing_certificates | list[str] | Certificate IDs | |

**State Transitions**:
- Created → Active (immediate)
- Active → Deleted (requires no dependencies)

---

### Role

IAM role that can be assumed by trusted entities.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| role_name | str | Unique name within account | 1-64 chars, `[\w+=,.@-]+` |
| role_id | str | Unique identifier | AROA + 16 alphanumeric |
| arn | str | Amazon Resource Name | `arn:aws:iam::{account}:role/{path}{name}` |
| path | str | Organizational path | Default "/" |
| create_date | datetime | Creation timestamp | UTC |
| assume_role_policy_document | str | Trust policy JSON | Required |
| description | str | Role description | Max 1000 chars |
| max_session_duration | int | Max assume duration seconds | 3600-43200, default 3600 |
| permission_boundary | str | Policy ARN for boundary | Optional |
| tags | dict[str, str] | Resource tags | Max 50 tags |
| inline_policies | dict[str, str] | Policy name → document | |
| attached_policies | list[str] | Attached policy ARNs | Max 10 |
| instance_profiles | list[str] | Instance profile names | |
| last_used | RoleLastUsed | Last assume information | Auto-updated |

**Service-Linked Role Fields** (additional):
| Field | Type | Description |
|-------|------|-------------|
| is_service_linked | bool | True for service-linked roles |
| service_name | str | e.g., "elasticmapreduce.amazonaws.com" |

---

### Group

Collection of IAM users for bulk permission assignment.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| group_name | str | Unique name within account | 1-128 chars, `[\w+=,.@-]+` |
| group_id | str | Unique identifier | AGPA + 16 alphanumeric |
| arn | str | Amazon Resource Name | `arn:aws:iam::{account}:group/{path}{name}` |
| path | str | Organizational path | Default "/" |
| create_date | datetime | Creation timestamp | UTC |
| users | list[str] | Member user names | |
| inline_policies | dict[str, str] | Policy name → document | |
| attached_policies | list[str] | Attached policy ARNs | Max 10 |

---

### ManagedPolicy

Standalone policy that can be attached to multiple principals.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| policy_name | str | Unique name within account | 1-128 chars |
| policy_id | str | Unique identifier | ANPA + 16 alphanumeric |
| arn | str | Amazon Resource Name | `arn:aws:iam::{account}:policy/{path}{name}` |
| path | str | Organizational path | Default "/" |
| create_date | datetime | Creation timestamp | UTC |
| update_date | datetime | Last update timestamp | UTC |
| description | str | Policy description | Max 1000 chars |
| default_version_id | str | Default version ID | e.g., "v1" |
| versions | list[PolicyVersion] | Policy versions | Max 5 |
| attachment_count | int | Number of attachments | Auto-computed |
| is_attachable | bool | Can be attached | True for customer policies |
| tags | dict[str, str] | Resource tags | Max 50 tags |

---

### PolicyVersion

A specific version of a managed policy.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| version_id | str | Version identifier | "v1", "v2", etc. |
| document | str | Policy document JSON | Max 6144 chars |
| is_default_version | bool | Is this the default | Only one per policy |
| create_date | datetime | Creation timestamp | UTC |

---

### InstanceProfile

Container for roles that can be assumed by EC2 instances.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| instance_profile_name | str | Unique name | 1-128 chars |
| instance_profile_id | str | Unique identifier | AIPA + 16 alphanumeric |
| arn | str | Amazon Resource Name | `arn:aws:iam::{account}:instance-profile/{path}{name}` |
| path | str | Organizational path | Default "/" |
| create_date | datetime | Creation timestamp | UTC |
| roles | list[str] | Role names (max 1) | Max 1 role |
| tags | dict[str, str] | Resource tags | Max 50 tags |

---

### AccessKey

Credential pair for programmatic AWS access.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| access_key_id | str | Key identifier | AKIA/LKIA + 16 alphanumeric |
| secret_access_key | str | Secret key | 40 chars, base64 |
| status | str | Active or Inactive | Enum: Active, Inactive |
| create_date | datetime | Creation timestamp | UTC |
| user_name | str | Owner user name | Required |

---

### AccessKeyLastUsed

Tracking information for access key usage.

| Field | Type | Description |
|-------|------|-------------|
| access_key_id | str | Key identifier |
| last_used_date | datetime | Last usage timestamp |
| service_name | str | Last AWS service used |
| region | str | Last region used |

---

### LoginProfile

Console access credentials for a user.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| user_name | str | Owner user name | Required |
| create_date | datetime | Creation timestamp | UTC |
| password_reset_required | bool | Force password change | Default: False |

---

### VirtualMFADevice

Software-based MFA device.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| serial_number | str | Device ARN | `arn:aws:iam::{account}:mfa/{name}` |
| base32_string_seed | str | TOTP seed (Base32) | Only returned on create |
| qr_code_png | bytes | QR code image | Only returned on create |
| enable_date | datetime | When enabled | Set on EnableMfaDevice |
| user | str | Associated user ARN | Set on EnableMfaDevice |
| tags | dict[str, str] | Resource tags | Max 50 tags |

---

### SAMLProvider

SAML 2.0 identity provider for federation.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| arn | str | Provider ARN | `arn:aws:iam::{account}:saml-provider/{name}` |
| name | str | Provider name | 1-128 chars |
| saml_metadata_document | str | SAML metadata XML | Max 10MB |
| create_date | datetime | Creation timestamp | UTC |
| valid_until | datetime | Metadata expiration | From metadata |
| tags | dict[str, str] | Resource tags | Max 50 tags |

---

### OIDCProvider

OpenID Connect identity provider for web identity federation.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| arn | str | Provider ARN | `arn:aws:iam::{account}:oidc-provider/{url}` |
| url | str | Provider URL | Must be HTTPS |
| client_id_list | list[str] | Allowed client IDs | Max 100 |
| thumbprint_list | list[str] | Certificate thumbprints | Max 5 |
| create_date | datetime | Creation timestamp | UTC |
| tags | dict[str, str] | Resource tags | Max 50 tags |

---

### ServerCertificate

SSL/TLS certificate for HTTPS.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| server_certificate_name | str | Certificate name | 1-128 chars |
| server_certificate_id | str | Unique identifier | ASCA + 16 alphanumeric |
| arn | str | Certificate ARN | `arn:aws:iam::{account}:server-certificate/{path}{name}` |
| path | str | Organizational path | Default "/" |
| certificate_body | str | PEM-encoded certificate | |
| certificate_chain | str | PEM-encoded chain | Optional |
| upload_date | datetime | Upload timestamp | UTC |
| expiration | datetime | Certificate expiration | From certificate |
| tags | dict[str, str] | Resource tags | Max 50 tags |

---

### ServiceSpecificCredential

Credentials for specific AWS services (CodeCommit, Cassandra).

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| service_specific_credential_id | str | Credential ID | 20 chars alphanumeric |
| user_name | str | Owner user name | Required |
| service_name | str | Target service | codecommit, cassandra |
| service_user_name | str | Service-specific username | Generated |
| service_password | str | Service-specific password | Only returned on create |
| status | str | Active or Inactive | Enum |
| create_date | datetime | Creation timestamp | UTC |

---

### SSHPublicKey

SSH public key for CodeCommit access.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| ssh_public_key_id | str | Key identifier | APKA + 16 alphanumeric |
| user_name | str | Owner user name | Required |
| ssh_public_key_body | str | Public key content | SSH format |
| status | str | Active or Inactive | Enum |
| upload_date | datetime | Upload timestamp | UTC |
| fingerprint | str | Key fingerprint | Computed |

---

### SigningCertificate

X.509 signing certificate.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| certificate_id | str | Certificate ID | 24 chars |
| user_name | str | Owner user name | Required |
| certificate_body | str | PEM certificate | |
| status | str | Active or Inactive | Enum |
| upload_date | datetime | Upload timestamp | UTC |

---

### PasswordPolicy

Account-level password requirements.

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| minimum_password_length | int | Minimum chars | 6 |
| require_symbols | bool | Require special chars | False |
| require_numbers | bool | Require digits | False |
| require_uppercase_characters | bool | Require uppercase | False |
| require_lowercase_characters | bool | Require lowercase | False |
| allow_users_to_change_password | bool | Users can change | True |
| expire_passwords | bool | Passwords expire | False |
| max_password_age | int | Days until expiry | 0 (never) |
| password_reuse_prevention | int | History to check | 0 (none) |
| hard_expiry | bool | Block after expiry | False |

---

### RoleLastUsed

Role usage tracking information.

| Field | Type | Description |
|-------|------|-------------|
| last_used_date | datetime | Last assume timestamp |
| region | str | Region where assumed |

---

## Relationships

```
User ──────────────────────────────────────────────────────────────
  │
  ├── belongs_to ──────────► Group (many-to-many)
  ├── has ──────────────────► AccessKey (one-to-many, max 2)
  ├── has ──────────────────► LoginProfile (one-to-one, optional)
  ├── has ──────────────────► VirtualMFADevice (one-to-many, max 8)
  ├── has ──────────────────► ServiceSpecificCredential (one-to-many)
  ├── has ──────────────────► SSHPublicKey (one-to-many)
  ├── has ──────────────────► SigningCertificate (one-to-many)
  ├── has_inline ───────────► InlinePolicy (one-to-many)
  ├── has_attached ─────────► ManagedPolicy (one-to-many, max 10)
  └── has_boundary ─────────► ManagedPolicy (one-to-one, optional)

Role ──────────────────────────────────────────────────────────────
  │
  ├── belongs_to ──────────► InstanceProfile (one-to-one)
  ├── has_inline ───────────► InlinePolicy (one-to-many)
  ├── has_attached ─────────► ManagedPolicy (one-to-many, max 10)
  └── has_boundary ─────────► ManagedPolicy (one-to-one, optional)

Group ─────────────────────────────────────────────────────────────
  │
  ├── contains ─────────────► User (one-to-many)
  ├── has_inline ───────────► InlinePolicy (one-to-many)
  └── has_attached ─────────► ManagedPolicy (one-to-many, max 10)

InstanceProfile ───────────────────────────────────────────────────
  │
  └── contains ─────────────► Role (one-to-one)

ManagedPolicy ─────────────────────────────────────────────────────
  │
  ├── has ──────────────────► PolicyVersion (one-to-many, max 5)
  └── attached_to ──────────► User/Role/Group (many-to-many)
```

## Validation Rules

### Name Patterns

| Entity | Pattern | Example |
|--------|---------|---------|
| User/Role/Group name | `[\w+=,.@-]+` | `my-user_123` |
| Policy name | `[\w+=,.@-]+` | `MyPolicy-v2` |
| Path | `(/[a-zA-Z0-9._-]+)*/?` | `/engineering/team1/` |

### Limits

| Resource | Limit | Notes |
|----------|-------|-------|
| Users per account | 5000 | IAM quota |
| Groups per account | 300 | IAM quota |
| Roles per account | 1000 | IAM quota |
| Policies per account | 1500 | Customer managed |
| Groups per user | 10 | |
| Attached policies per principal | 10 | |
| Policy versions | 5 | Per managed policy |
| Access keys per user | 2 | |
| MFA devices per user | 8 | |
| Tags per resource | 50 | |
| Policy document size | 6144 bytes | |
| Trust policy size | 2048 bytes | |

## Store Implementation

```python
@dataclass
class User:
    user_name: str
    user_id: str
    arn: str
    path: str = "/"
    create_date: datetime = field(default_factory=datetime.utcnow)
    permission_boundary: Optional[str] = None
    tags: dict[str, str] = field(default_factory=dict)
    groups: list[str] = field(default_factory=list)
    inline_policies: dict[str, str] = field(default_factory=dict)
    attached_policies: list[str] = field(default_factory=list)
    login_profile: Optional[LoginProfile] = None
    mfa_devices: list[str] = field(default_factory=list)
    access_keys: list[str] = field(default_factory=list)
    service_specific_credentials: list[str] = field(default_factory=list)
    ssh_public_keys: list[str] = field(default_factory=list)
    signing_certificates: list[str] = field(default_factory=list)


class IamStore(BaseStore):
    # Principal resources
    users: dict[str, User] = CrossRegionAttribute(default=dict)
    groups: dict[str, Group] = CrossRegionAttribute(default=dict)
    roles: dict[str, Role] = CrossRegionAttribute(default=dict)
    instance_profiles: dict[str, InstanceProfile] = CrossRegionAttribute(default=dict)

    # Policies
    policies: dict[str, ManagedPolicy] = CrossRegionAttribute(default=dict)

    # AWS managed policies (shared across accounts)
    aws_managed_policies: dict[str, AWSManagedPolicy] = CrossAccountAttribute(default=dict)

    # Credentials
    access_keys: dict[str, AccessKey] = CrossRegionAttribute(default=dict)
    access_key_last_used: dict[str, AccessKeyLastUsed] = CrossRegionAttribute(default=dict)

    # MFA
    virtual_mfa_devices: dict[str, VirtualMFADevice] = CrossRegionAttribute(default=dict)

    # Identity Providers
    saml_providers: dict[str, SAMLProvider] = CrossRegionAttribute(default=dict)
    oidc_providers: dict[str, OIDCProvider] = CrossRegionAttribute(default=dict)

    # Certificates
    server_certificates: dict[str, ServerCertificate] = CrossRegionAttribute(default=dict)

    # Account settings
    account_aliases: list[str] = CrossRegionAttribute(default=list)
    password_policy: Optional[PasswordPolicy] = CrossRegionAttribute(default=None)

    # Tagging
    TAGS: TaggingService = CrossAccountAttribute(default=TaggingService)


iam_stores = AccountRegionBundle("iam", IamStore)
```
