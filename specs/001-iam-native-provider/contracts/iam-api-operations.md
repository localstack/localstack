# IAM API Operations Contract

**Feature**: 001-iam-native-provider
**Date**: 2025-12-12
**Total Operations**: 164

## Overview

This contract defines the 164 IAM API operations to be implemented, organized by resource type.
All operations must match AWS behavior exactly (response structure, error codes, validation).

## Operations by Category

### User Operations (29)

| Operation | Priority | Description |
|-----------|----------|-------------|
| CreateUser | P1 | Create a new IAM user |
| GetUser | P1 | Get user details |
| ListUsers | P1 | List all users |
| UpdateUser | P1 | Update user name/path |
| DeleteUser | P1 | Delete a user |
| CreateAccessKey | P1 | Create access key for user |
| DeleteAccessKey | P1 | Delete access key |
| GetAccessKeyLastUsed | P1 | Get key usage info |
| ListAccessKeys | P1 | List user's access keys |
| UpdateAccessKey | P1 | Activate/deactivate key |
| CreateLoginProfile | P2 | Create console login |
| DeleteLoginProfile | P2 | Delete console login |
| GetLoginProfile | P2 | Get login profile |
| UpdateLoginProfile | P2 | Update password/reset |
| PutUserPolicy | P1 | Add inline policy |
| DeleteUserPolicy | P1 | Remove inline policy |
| GetUserPolicy | P1 | Get inline policy |
| ListUserPolicies | P1 | List inline policies |
| AttachUserPolicy | P1 | Attach managed policy |
| DetachUserPolicy | P1 | Detach managed policy |
| ListAttachedUserPolicies | P1 | List attached policies |
| PutUserPermissionsBoundary | P2 | Set permission boundary |
| DeleteUserPermissionsBoundary | P2 | Remove boundary |
| AddUserToGroup | P1 | Add user to group |
| RemoveUserFromGroup | P1 | Remove from group |
| ListGroupsForUser | P1 | List user's groups |
| TagUser | P2 | Add tags |
| UntagUser | P2 | Remove tags |
| ListUserTags | P2 | List tags |

### Role Operations (33)

| Operation | Priority | Description |
|-----------|----------|-------------|
| CreateRole | P1 | Create a new role |
| GetRole | P1 | Get role details |
| ListRoles | P1 | List all roles |
| UpdateRole | P2 | Update max session |
| UpdateRoleDescription | P2 | Update description |
| DeleteRole | P1 | Delete a role |
| UpdateAssumeRolePolicy | P1 | Update trust policy |
| PutRolePolicy | P1 | Add inline policy |
| DeleteRolePolicy | P1 | Remove inline policy |
| GetRolePolicy | P1 | Get inline policy |
| ListRolePolicies | P1 | List inline policies |
| AttachRolePolicy | P1 | Attach managed policy |
| DetachRolePolicy | P1 | Detach managed policy |
| ListAttachedRolePolicies | P1 | List attached policies |
| PutRolePermissionsBoundary | P2 | Set permission boundary |
| DeleteRolePermissionsBoundary | P2 | Remove boundary |
| TagRole | P2 | Add tags |
| UntagRole | P2 | Remove tags |
| ListRoleTags | P2 | List tags |
| CreateServiceLinkedRole | P2 | Create service-linked role |
| DeleteServiceLinkedRole | P2 | Delete service-linked role |
| GetServiceLinkedRoleDeletionStatus | P2 | Check deletion status |
| CreateInstanceProfile | P2 | Create instance profile |
| DeleteInstanceProfile | P2 | Delete instance profile |
| GetInstanceProfile | P2 | Get profile details |
| ListInstanceProfiles | P2 | List all profiles |
| ListInstanceProfilesForRole | P2 | List profiles for role |
| AddRoleToInstanceProfile | P2 | Add role to profile |
| RemoveRoleFromInstanceProfile | P2 | Remove role from profile |
| TagInstanceProfile | P2 | Add tags |
| UntagInstanceProfile | P2 | Remove tags |
| ListInstanceProfileTags | P2 | List tags |

### Group Operations (18)

| Operation | Priority | Description |
|-----------|----------|-------------|
| CreateGroup | P1 | Create a new group |
| GetGroup | P1 | Get group with members |
| ListGroups | P1 | List all groups |
| UpdateGroup | P1 | Update name/path |
| DeleteGroup | P1 | Delete a group |
| PutGroupPolicy | P1 | Add inline policy |
| DeleteGroupPolicy | P1 | Remove inline policy |
| GetGroupPolicy | P1 | Get inline policy |
| ListGroupPolicies | P1 | List inline policies |
| AttachGroupPolicy | P1 | Attach managed policy |
| DetachGroupPolicy | P1 | Detach managed policy |
| ListAttachedGroupPolicies | P1 | List attached policies |
| AddUserToGroup | P1 | Add user to group |
| RemoveUserFromGroup | P1 | Remove user from group |
| ListGroupsForUser | P1 | List groups for user |
| TagGroup | P3 | Add tags |
| UntagGroup | P3 | Remove tags |
| ListGroupTags | P3 | List tags |

### Policy Operations (26)

| Operation | Priority | Description |
|-----------|----------|-------------|
| CreatePolicy | P1 | Create managed policy |
| GetPolicy | P1 | Get policy metadata |
| ListPolicies | P1 | List all policies |
| DeletePolicy | P1 | Delete policy |
| CreatePolicyVersion | P1 | Add policy version |
| DeletePolicyVersion | P1 | Delete version |
| GetPolicyVersion | P1 | Get version document |
| ListPolicyVersions | P1 | List all versions |
| SetDefaultPolicyVersion | P1 | Set default version |
| ListEntitiesForPolicy | P2 | List attachments |
| TagPolicy | P2 | Add tags |
| UntagPolicy | P2 | Remove tags |
| ListPolicyTags | P2 | List tags |
| SimulateCustomPolicy | P3 | Simulate permissions |
| SimulatePrincipalPolicy | P3 | Simulate for principal |
| GetContextKeysForCustomPolicy | P3 | Get context keys |
| GetContextKeysForPrincipalPolicy | P3 | Get principal keys |
| ListPoliciesGrantingServiceAccess | P3 | List service access |
| GetAccountAuthorizationDetails | P3 | Full account dump |
| GenerateServiceLastAccessedDetails | P3 | Start access report |
| GetServiceLastAccessedDetails | P3 | Get access report |
| GetServiceLastAccessedDetailsWithEntities | P3 | Detailed report |

### MFA Operations (8)

| Operation | Priority | Description |
|-----------|----------|-------------|
| CreateVirtualMfaDevice | P3 | Create MFA device |
| DeleteVirtualMfaDevice | P3 | Delete device |
| ListVirtualMFADevices | P3 | List all devices |
| EnableMfaDevice | P3 | Enable for user |
| DeactivateMfaDevice | P3 | Disable for user |
| ResyncMFADevice | P3 | Resync TOTP |
| ListMFADevices | P3 | List user's devices |
| GetMFADevice | P3 | Get device details |
| TagMFADevice | P3 | Add tags |
| UntagMFADevice | P3 | Remove tags |
| ListMFADeviceTags | P3 | List tags |

### OIDC Provider Operations (7)

| Operation | Priority | Description |
|-----------|----------|-------------|
| CreateOpenIDConnectProvider | P3 | Create OIDC provider |
| DeleteOpenIDConnectProvider | P3 | Delete provider |
| GetOpenIDConnectProvider | P3 | Get provider details |
| ListOpenIDConnectProviders | P3 | List all providers |
| AddClientIDToOpenIDConnectProvider | P3 | Add client ID |
| RemoveClientIDFromOpenIDConnectProvider | P3 | Remove client ID |
| UpdateOpenIDConnectProviderThumbprint | P3 | Update thumbprint |
| TagOpenIDConnectProvider | P3 | Add tags |
| UntagOpenIDConnectProvider | P3 | Remove tags |
| ListOpenIDConnectProviderTags | P3 | List tags |

### SAML Provider Operations (6)

| Operation | Priority | Description |
|-----------|----------|-------------|
| CreateSAMLProvider | P3 | Create SAML provider |
| DeleteSAMLProvider | P3 | Delete provider |
| GetSAMLProvider | P3 | Get provider details |
| ListSAMLProviders | P3 | List all providers |
| UpdateSAMLProvider | P3 | Update metadata |
| TagSAMLProvider | P3 | Add tags |
| UntagSAMLProvider | P3 | Remove tags |
| ListSAMLProviderTags | P3 | List tags |

### Server Certificate Operations (7)

| Operation | Priority | Description |
|-----------|----------|-------------|
| UploadServerCertificate | P3 | Upload certificate |
| DeleteServerCertificate | P3 | Delete certificate |
| GetServerCertificate | P3 | Get certificate |
| ListServerCertificates | P3 | List all certificates |
| UpdateServerCertificate | P3 | Update name/path |
| TagServerCertificate | P3 | Add tags |
| UntagServerCertificate | P3 | Remove tags |
| ListServerCertificateTags | P3 | List tags |

### SSH Key Operations (5)

| Operation | Priority | Description |
|-----------|----------|-------------|
| UploadSSHPublicKey | P3 | Upload SSH key |
| DeleteSSHPublicKey | P3 | Delete SSH key |
| GetSSHPublicKey | P3 | Get SSH key |
| UpdateSSHPublicKey | P3 | Activate/deactivate |
| ListSSHPublicKeys | P3 | List user's SSH keys |

### Signing Certificate Operations (4)

| Operation | Priority | Description |
|-----------|----------|-------------|
| UploadSigningCertificate | P3 | Upload certificate |
| DeleteSigningCertificate | P3 | Delete certificate |
| UpdateSigningCertificate | P3 | Activate/deactivate |
| ListSigningCertificates | P3 | List certificates |

### Service-Specific Credential Operations (5)

| Operation | Priority | Description |
|-----------|----------|-------------|
| CreateServiceSpecificCredential | P2 | Create credential |
| DeleteServiceSpecificCredential | P2 | Delete credential |
| ListServiceSpecificCredentials | P2 | List credentials |
| UpdateServiceSpecificCredential | P2 | Activate/deactivate |
| ResetServiceSpecificCredential | P2 | Reset password |

### Account Operations (10)

| Operation | Priority | Description |
|-----------|----------|-------------|
| CreateAccountAlias | P3 | Set account alias |
| DeleteAccountAlias | P3 | Remove alias |
| ListAccountAliases | P3 | List aliases |
| GetAccountSummary | P3 | Get quotas/counts |
| UpdateAccountPasswordPolicy | P3 | Set password policy |
| DeleteAccountPasswordPolicy | P3 | Remove policy |
| GetAccountPasswordPolicy | P3 | Get password policy |
| GenerateCredentialReport | P3 | Generate report |
| GetCredentialReport | P3 | Download report |
| ChangePassword | P3 | User password change |

### Organizations Integration (8)

| Operation | Priority | Description |
|-----------|----------|-------------|
| EnableOrganizationsRootCredentialsManagement | P3 | Enable org root |
| DisableOrganizationsRootCredentialsManagement | P3 | Disable org root |
| EnableOrganizationsRootSessions | P3 | Enable root sessions |
| DisableOrganizationsRootSessions | P3 | Disable root sessions |
| ListOrganizationsFeatures | P3 | List features |
| GenerateOrganizationsAccessReport | P3 | Generate report |
| GetOrganizationsAccessReport | P3 | Get report |
| SetSecurityTokenServicePreferences | P3 | Set STS preferences |

## Error Codes

All operations must return AWS-compliant errors:

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| NoSuchEntity | 404 | Resource not found |
| EntityAlreadyExists | 409 | Duplicate resource |
| DeleteConflict | 409 | Resource has dependencies |
| LimitExceeded | 409 | Quota exceeded |
| InvalidInput | 400 | Invalid parameter |
| MalformedPolicyDocument | 400 | Invalid policy JSON |
| ServiceNotSupported | 400 | Unsupported service |
| ConcurrentModification | 409 | Race condition |
| ValidationError | 400 | Validation failed |

## Pagination Contract

All list operations must support:
- `Marker`: Token for next page
- `MaxItems`: Page size (default varies by operation)
- Response includes `IsTruncated` boolean
- Response includes `Marker` for next page when truncated

## Response Format

All responses must match AWS JSON structure exactly:
- Use PascalCase for field names
- Include `ResponseMetadata` with `RequestId`
- Match exact nesting and array structures
