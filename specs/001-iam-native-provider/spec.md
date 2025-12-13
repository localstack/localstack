# Feature Specification: Native IAM Provider (Remove Moto Dependency)

**Feature Branch**: `001-iam-native-provider`
**Created**: 2025-12-12
**Status**: Draft
**Input**: User description: "Remove moto from IAM service and implement native provider with full AWS parity"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Core IAM Resource Management (Priority: P1)

As a developer using LocalStack, I want to create, manage, and delete IAM users, roles, groups, and policies so that I can test my AWS-dependent applications locally without connecting to real AWS infrastructure.

**Why this priority**: Core IAM resources (users, roles, groups, policies) are the foundation of all IAM operations. Every other IAM feature depends on these fundamental resources existing and functioning correctly. Without this, no other IAM functionality can work.

**Independent Test**: Can be fully tested by creating IAM users, roles, groups, and policies via AWS CLI/SDK and verifying they persist, can be listed, updated, and deleted correctly.

**Acceptance Scenarios**:

1. **Given** a fresh LocalStack instance, **When** I create an IAM user with `CreateUser`, **Then** the user is persisted and retrievable via `GetUser` with correct ARN, user ID, and creation date
2. **Given** an existing IAM user, **When** I delete the user with `DeleteUser`, **Then** the user is removed and `GetUser` returns `NoSuchEntity` error
3. **Given** a fresh LocalStack instance, **When** I create an IAM role with a trust policy, **Then** the role is persisted with correct ARN, assume role policy document, and can be assumed via STS
4. **Given** a fresh LocalStack instance, **When** I create an IAM group and add users to it, **Then** the group membership is correctly tracked and queryable
5. **Given** a fresh LocalStack instance, **When** I create a managed policy with multiple versions, **Then** versions are tracked and the default version can be changed

---

### User Story 2 - Access Key and Credential Management (Priority: P1)

As a developer, I want to create and manage IAM access keys so that I can authenticate API requests to LocalStack services using standard AWS credential patterns.

**Why this priority**: Access keys are essential for authenticating any AWS API call. Without working access key management, developers cannot properly test their applications' authentication flows.

**Independent Test**: Can be tested by creating access keys for users, using those keys to authenticate AWS CLI commands, and verifying key rotation/deletion works.

**Acceptance Scenarios**:

1. **Given** an existing IAM user, **When** I create an access key with `CreateAccessKey`, **Then** I receive a valid access key ID and secret key that can authenticate API requests
2. **Given** an active access key, **When** I deactivate it with `UpdateAccessKey`, **Then** subsequent API requests using that key are rejected
3. **Given** multiple access keys for a user, **When** I list access keys, **Then** all keys are returned with correct status and creation dates
4. **Given** an access key, **When** I query `GetAccessKeyLastUsed`, **Then** I receive accurate last-used information including service name and region

---

### User Story 3 - Policy Attachment and Inline Policies (Priority: P1)

As a developer, I want to attach managed policies and create inline policies for users, roles, and groups so that I can test permission configurations locally.

**Why this priority**: Policy attachment is fundamental to IAM's authorization model. Applications that depend on IAM permissions need to test that policies are correctly attached and recognized.

**Independent Test**: Can be tested by attaching policies to principals, listing attached policies, and verifying inline policy CRUD operations work correctly.

**Acceptance Scenarios**:

1. **Given** an existing role and managed policy, **When** I attach the policy with `AttachRolePolicy`, **Then** the attachment is recorded and visible via `ListAttachedRolePolicies`
2. **Given** a role with an attached policy, **When** I detach the policy, **Then** the policy is removed from the role's attached policies list
3. **Given** an existing user, **When** I put an inline policy with `PutUserPolicy`, **Then** the policy is stored and retrievable via `GetUserPolicy`
4. **Given** a user with inline policies, **When** I list policies with `ListUserPolicies`, **Then** all inline policy names are returned

---

### User Story 4 - Instance Profiles for EC2 Integration (Priority: P2)

As a developer testing EC2-related workflows, I want to create and manage instance profiles so that I can assign IAM roles to EC2 instances in my local tests.

**Why this priority**: Instance profiles are critical for EC2 workloads but have a narrower use case than core IAM resources. Many applications can function without instance profiles.

**Independent Test**: Can be tested by creating instance profiles, adding/removing roles, and verifying the profile can be referenced in EC2 instance launches.

**Acceptance Scenarios**:

1. **Given** a fresh LocalStack instance, **When** I create an instance profile and add a role to it, **Then** the profile is correctly associated with the role
2. **Given** an instance profile with a role, **When** I remove the role, **Then** the profile exists but has no associated role
3. **Given** an instance profile, **When** I tag and list tags, **Then** tags are correctly stored and retrievable

---

### User Story 5 - Service-Linked Roles (Priority: P2)

As a developer, I want to create and manage service-linked roles so that I can test AWS service integrations that require automatic role creation.

**Why this priority**: Service-linked roles are required by many AWS services (Lambda, ECS, etc.) but are typically auto-created. Supporting them enables more realistic service integrations.

**Independent Test**: Can be tested by creating service-linked roles for various AWS services and verifying they have correct permissions and trust policies.

**Acceptance Scenarios**:

1. **Given** a fresh LocalStack instance, **When** I create a service-linked role for a supported AWS service, **Then** the role is created with the correct trust policy and attached managed policy
2. **Given** a service-linked role, **When** I delete it, **Then** the deletion status can be tracked and the role is eventually removed
3. **Given** an unsupported service name, **When** I attempt to create a service-linked role, **Then** an appropriate error is returned

---

### User Story 6 - Service-Specific Credentials (Priority: P2)

As a developer using CodeCommit or Keyspaces, I want to create service-specific credentials so that I can test integrations requiring these specialized credentials.

**Why this priority**: Service-specific credentials are needed only for specific AWS services (CodeCommit, Cassandra/Keyspaces). While important for those use cases, they don't affect core IAM functionality.

**Independent Test**: Can be tested by creating service-specific credentials for supported services and verifying credential lifecycle operations.

**Acceptance Scenarios**:

1. **Given** an existing IAM user, **When** I create service-specific credentials for CodeCommit, **Then** I receive a service-specific username and password
2. **Given** existing service-specific credentials, **When** I reset the password, **Then** a new password is generated and the old one is invalidated
3. **Given** service-specific credentials, **When** I update the status to inactive, **Then** the credentials can no longer be used for authentication

---

### User Story 7 - MFA Device Management (Priority: P3)

As a security-conscious developer, I want to manage virtual MFA devices so that I can test multi-factor authentication workflows.

**Why this priority**: MFA is important for security but many development/testing workflows don't require it. Core IAM functionality works without MFA support.

**Independent Test**: Can be tested by creating virtual MFA devices, enabling them for users, and listing/deactivating them.

**Acceptance Scenarios**:

1. **Given** a fresh LocalStack instance, **When** I create a virtual MFA device, **Then** I receive a base32 seed for TOTP generation
2. **Given** a virtual MFA device, **When** I enable it for a user with valid TOTP codes, **Then** the device is associated with the user
3. **Given** an enabled MFA device, **When** I deactivate it, **Then** the device is removed from the user's MFA list

---

### User Story 8 - Federation Providers (OIDC and SAML) (Priority: P3)

As a developer testing federated authentication, I want to manage OIDC and SAML identity providers so that I can test federated role assumption.

**Why this priority**: Federation is an advanced feature used for specific enterprise scenarios. Most LocalStack users don't need federation for basic testing.

**Independent Test**: Can be tested by creating OIDC/SAML providers, updating their configurations, and verifying they can be used for `AssumeRoleWithWebIdentity` or `AssumeRoleWithSAML`.

**Acceptance Scenarios**:

1. **Given** a fresh LocalStack instance, **When** I create an OIDC provider with a valid URL, **Then** the provider is stored with client IDs and thumbprints
2. **Given** an OIDC provider, **When** I add or remove client IDs, **Then** the changes are persisted
3. **Given** a fresh LocalStack instance, **When** I create a SAML provider with metadata, **Then** the provider is stored and can be referenced in trust policies

---

### User Story 9 - Account-Level Operations (Priority: P3)

As an administrator, I want to manage account aliases and password policies so that I can test account configuration workflows.

**Why this priority**: Account-level settings are administrative tasks that most application tests don't interact with directly.

**Independent Test**: Can be tested by setting account aliases, configuring password policies, and generating credential reports.

**Acceptance Scenarios**:

1. **Given** a fresh LocalStack instance, **When** I create an account alias, **Then** the alias is stored and returned by `ListAccountAliases`
2. **Given** a fresh instance, **When** I update the account password policy, **Then** the policy requirements are enforced on new password operations
3. **Given** users with credentials, **When** I generate a credential report, **Then** a CSV report is produced with user credential information

---

### User Story 10 - Full AWS API Parity (Priority: P3)

As a developer, I want all 164 IAM API operations to work identically to AWS so that I can test any IAM-related workflow without unexpected behavior differences.

**Why this priority**: While core operations cover most use cases, full parity ensures LocalStack can be used as a complete drop-in replacement for AWS IAM in development and testing.

**Independent Test**: Can be tested by running the full IAM test suite against both LocalStack and real AWS and comparing responses.

**Acceptance Scenarios**:

1. **Given** any valid IAM API request, **When** I send it to LocalStack, **Then** the response format matches AWS exactly (structure, field names, error codes)
2. **Given** an invalid IAM API request, **When** I send it to LocalStack, **Then** the error response matches AWS (error code, error message format)
3. **Given** paginated list operations, **When** I use markers and max items, **Then** pagination works identically to AWS

---

### Edge Cases

- What happens when a user is deleted while still having attached policies? (Policies must be detached first, matching AWS behavior)
- How does the system handle circular group memberships? (Not allowed in AWS IAM)
- What happens when deleting a role that is referenced by instance profiles? (Must remove from instance profiles first)
- How does the system handle policy version limits? (Maximum 5 versions per policy, oldest non-default must be deleted)
- What happens when creating duplicate resources? (EntityAlreadyExists error with appropriate message)
- How are ARN formats validated? (Must match AWS ARN patterns exactly)
- What happens with malformed policy documents? (MalformedPolicyDocument error with specific validation message)
- How does the system handle the 10 access key limit per user? (LimitExceeded error)

## Requirements *(mandatory)*

### Functional Requirements

#### Core Resource Management
- **FR-001**: System MUST support full CRUD operations for IAM users including path-based organization
- **FR-002**: System MUST support full CRUD operations for IAM roles including trust policies and session duration
- **FR-003**: System MUST support full CRUD operations for IAM groups including membership management
- **FR-004**: System MUST support managed policy lifecycle including versioning (up to 5 versions)
- **FR-005**: System MUST support inline policy CRUD for users, roles, and groups
- **FR-006**: System MUST support instance profile management including role association

#### Credential Management
- **FR-007**: System MUST support access key creation, rotation, and deletion (max 2 active keys per user)
- **FR-008**: System MUST track access key last used information (service, region, timestamp)
- **FR-009**: System MUST support login profile management for console access simulation
- **FR-010**: System MUST support service-specific credentials for CodeCommit and Cassandra services

#### Advanced Features
- **FR-011**: System MUST support service-linked role creation for all AWS services that use them
- **FR-012**: System MUST support virtual MFA device creation and user association
- **FR-013**: System MUST support OIDC identity provider management including client IDs and thumbprints
- **FR-014**: System MUST support SAML identity provider management including metadata documents
- **FR-015**: System MUST support server certificate upload and management
- **FR-016**: System MUST support SSH public key management for CodeCommit

#### Policy Features
- **FR-017**: System MUST support permission boundaries for users and roles
- **FR-018**: System MUST support policy attachment to users, roles, and groups
- **FR-019**: System MUST support policy simulation via `SimulatePrincipalPolicy` and `SimulateCustomPolicy`
- **FR-020**: System MUST pre-load AWS managed policies for attachment to principals

#### Account Features
- **FR-021**: System MUST support account alias management
- **FR-022**: System MUST support account password policy configuration
- **FR-023**: System MUST support credential report generation
- **FR-024**: System MUST support account summary statistics

#### Multi-Account and State Management
- **FR-025**: System MUST support multi-account isolation (separate IAM state per AWS account ID)
- **FR-026**: System MUST persist IAM state across LocalStack restarts (when persistence is enabled)
- **FR-027**: System MUST support proper pagination for all list operations using markers

#### AWS Parity
- **FR-028**: System MUST return identical response structures to AWS for all 164 IAM API operations
- **FR-029**: System MUST return identical error responses to AWS (error codes, messages, HTTP status)
- **FR-030**: System MUST validate inputs identically to AWS (ARN formats, name patterns, document schemas)
- **FR-031**: System MUST generate resource IDs in AWS-compatible formats (AIDA*, AROA*, etc.)

#### Integration Requirements
- **FR-032**: System MUST integrate with STS for AssumeRole operations
- **FR-033**: System MUST provide access key validation for other LocalStack services
- **FR-034**: System MUST support CloudFormation resource provisioning for all IAM resource types

### Key Entities

- **User**: IAM identity with username, path, ARN, user ID, creation date, optional password policy, permission boundary, and tags
- **Role**: IAM identity with role name, path, ARN, role ID, trust policy (AssumeRolePolicyDocument), optional permission boundary, session duration, and tags
- **Group**: Collection of users with group name, path, ARN, group ID, and creation date
- **Policy**: Managed policy with ARN, policy ID, versions (up to 5), default version marker, attachment count, and tags
- **InlinePolicy**: Policy document embedded directly in a user, role, or group
- **AccessKey**: Credential pair with access key ID, secret key, status (Active/Inactive), creation date, and last used tracking
- **InstanceProfile**: Container for roles to be assumed by EC2 instances
- **VirtualMFADevice**: TOTP-based MFA device with serial number and seed
- **OIDCProvider**: OpenID Connect identity provider with URL, client IDs, and thumbprints
- **SAMLProvider**: SAML 2.0 identity provider with ARN and metadata document
- **ServerCertificate**: SSL/TLS certificate with certificate body, private key, and chain
- **ServiceLinkedRole**: Special role type created by AWS services with predefined permissions
- **ServiceSpecificCredential**: Credentials for specific services (CodeCommit, Cassandra)

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All 164 IAM API operations return responses matching AWS response structure (validated against AWS parity tests)
- **SC-002**: All existing IAM integration tests pass without modification after migration
- **SC-003**: IAM operations complete within comparable performance to current moto-based implementation (no more than 10% regression)
- **SC-004**: LocalStack IAM supports at least 10,000 IAM resources (users, roles, policies combined) per account without degradation
- **SC-005**: Zero moto imports remain in the IAM service module after migration
- **SC-006**: IAM state persists correctly across LocalStack restarts when persistence is enabled (100% state recovery)
- **SC-007**: Multi-account isolation is complete (no cross-account resource visibility or access)
- **SC-008**: CloudFormation can successfully provision all IAM resource types using the native provider
- **SC-009**: STS AssumeRole operations work correctly with native IAM roles
- **SC-010**: Error messages match AWS error formats for at least 95% of error scenarios (validated against AWS responses)

## Assumptions

- The existing IAM API definitions in `localstack/aws/api/iam/__init__.py` (auto-generated from AWS specs) will be reused
- The `AccountRegionBundle` pattern used by S3, Lambda, and other native providers is the appropriate architecture
- AWS managed policies data (~3.5MB) will be embedded or loaded from a data file
- Service-linked role definitions (60+ services) from the current implementation will be migrated
- The CloudFormation resource providers in `resource_providers/` will need updates but can largely be preserved
- Multi-region is not relevant for IAM (IAM is a global service in AWS)
- Policy evaluation/enforcement is out of scope for this feature (IAM stores policies but doesn't enforce them on API calls)

## Out of Scope

- Implementing a policy evaluation engine that enforces IAM permissions on LocalStack API calls
- AWS Organizations integration (separate service)
- IAM Access Analyzer functionality (separate service)
- Real MFA validation (TOTP codes will be accepted without cryptographic verification for testing purposes)
- Real federation with external OIDC/SAML providers (providers are stored but not used for actual authentication)
