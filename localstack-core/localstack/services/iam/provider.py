import base64
import copy
import csv
import hashlib
import inspect
import io
import json
import logging
import os
import random
import re
import string
import threading
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar
from urllib.parse import quote

from cryptography import x509
from moto.iam.models import IAMBackend, iam_backends

from localstack import config
from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.iam import (
    AccessKey,
    AccessKeyLastUsed,
    AccessKeyMetadata,
    AttachedPermissionsBoundary,
    AttachedPolicy,
    CreateAccessKeyResponse,
    CreateGroupResponse,
    CreateInstanceProfileResponse,
    CreateLoginProfileResponse,
    CreateOpenIDConnectProviderResponse,
    CreatePolicyResponse,
    CreatePolicyVersionResponse,
    CreateRoleResponse,
    CreateSAMLProviderResponse,
    CreateServiceLinkedRoleResponse,
    CreateServiceSpecificCredentialResponse,
    CreateUserResponse,
    CreateVirtualMFADeviceResponse,
    CredentialReportNotPresentException,
    DeleteConflictException,
    DeleteServiceLinkedRoleResponse,
    DeletionTaskIdType,
    DeletionTaskStatusType,
    EntityAlreadyExistsException,
    EntityType,
    GenerateCredentialReportResponse,
    GetAccessKeyLastUsedResponse,
    GetAccountAuthorizationDetailsResponse,
    GetAccountPasswordPolicyResponse,
    GetAccountSummaryResponse,
    GetCredentialReportResponse,
    GetGroupPolicyResponse,
    GetGroupResponse,
    GetInstanceProfileResponse,
    GetLoginProfileResponse,
    GetOpenIDConnectProviderResponse,
    GetPolicyResponse,
    GetPolicyVersionResponse,
    GetRolePolicyResponse,
    GetRoleResponse,
    GetSAMLProviderResponse,
    GetServerCertificateResponse,
    GetServiceLinkedRoleDeletionStatusResponse,
    GetSSHPublicKeyResponse,
    GetUserPolicyResponse,
    GetUserResponse,
    Group,
    GroupDetail,
    IamApi,
    InstanceProfile,
    InvalidInputException,
    LimitExceededException,
    ListAccessKeysResponse,
    ListAttachedGroupPoliciesResponse,
    ListAttachedRolePoliciesResponse,
    ListAttachedUserPoliciesResponse,
    ListEntitiesForPolicyResponse,
    ListGroupPoliciesResponse,
    ListGroupsForUserResponse,
    ListGroupsResponse,
    ListInstanceProfilesForRoleResponse,
    ListInstanceProfilesResponse,
    ListInstanceProfileTagsResponse,
    ListMFADevicesResponse,
    ListOpenIDConnectProvidersResponse,
    ListOpenIDConnectProviderTagsResponse,
    ListPoliciesResponse,
    ListPolicyTagsResponse,
    ListPolicyVersionsResponse,
    ListRolePoliciesResponse,
    ListRolesResponse,
    ListRoleTagsResponse,
    ListSAMLProvidersResponse,
    ListSAMLProviderTagsResponse,
    ListServerCertificatesResponse,
    ListServerCertificateTagsResponse,
    ListServiceSpecificCredentialsResponse,
    ListSigningCertificatesResponse,
    ListSSHPublicKeysResponse,
    ListUserPoliciesResponse,
    ListUsersResponse,
    ListUserTagsResponse,
    ListVirtualMFADevicesResponse,
    LoginProfile,
    MalformedCertificateException,
    MalformedPolicyDocumentException,
    ManagedPolicyDetail,
    MFADevice,
    NoSuchEntityException,
    OpenIDConnectProviderListEntry,
    OpenIDConnectProviderUrlType,
    PasswordPolicy,
    Policy,
    PolicyDetail,
    PolicyGroup,
    PolicyRole,
    PolicyUsageType,
    PolicyUser,
    PolicyVersion,
    ReportFormatType,
    ReportStateType,
    ResetServiceSpecificCredentialResponse,
    Role,
    RoleDetail,
    RoleLastUsed,
    SAMLMetadataDocumentType,
    SAMLProviderListEntry,
    SAMLProviderNameType,
    ServerCertificate,
    ServerCertificateMetadata,
    ServiceSpecificCredential,
    ServiceSpecificCredentialMetadata,
    SigningCertificate,
    SimulatePolicyResponse,
    SimulatePrincipalPolicyRequest,
    SSHPublicKey,
    SSHPublicKeyMetadata,
    Tag,
    UpdateRoleDescriptionResponse,
    UpdateRoleResponse,
    UpdateSAMLProviderResponse,
    UploadServerCertificateResponse,
    UploadSigningCertificateResponse,
    UploadSSHPublicKeyResponse,
    User,
    UserDetail,
    VirtualMFADevice,
    accessKeyIdType,
    allUsers,
    arnType,
    assertionEncryptionModeType,
    assignmentStatusType,
    authenticationCodeType,
    booleanObjectType,
    booleanType,
    certificateBodyType,
    certificateChainType,
    certificateIdType,
    clientIDListType,
    clientIDType,
    credentialAgeDays,
    customSuffixType,
    encodingType,
    entityListType,
    existingUserNameType,
    groupNameType,
    instanceProfileNameType,
    markerType,
    maxItemsType,
    maxPasswordAgeType,
    minimumPasswordLengthType,
    passwordReusePreventionType,
    passwordType,
    pathPrefixType,
    pathType,
    policyDescriptionType,
    policyDocumentType,
    policyNameType,
    policyPathType,
    policyScopeType,
    policyVersionIdType,
    privateKeyIdType,
    privateKeyType,
    publicKeyIdType,
    publicKeyMaterialType,
    roleDescriptionType,
    roleMaxSessionDurationType,
    roleNameType,
    serialNumberType,
    serverCertificateNameType,
    serviceName,
    serviceSpecificCredentialId,
    statusType,
    tagKeyListType,
    tagListType,
    thumbprintListType,
    userNameType,
    virtualMFADeviceName,
)
from localstack.aws.api.iam import (
    VirtualMFADevice as VirtualMFADeviceModel,
)
from localstack.aws.connect import connect_to
from localstack.constants import INTERNAL_AWS_SECRET_ACCESS_KEY, TAG_KEY_CUSTOM_ID
from localstack.services.iam.iam_patches import apply_iam_patches
from localstack.services.iam.models import (
    AccessKeyEntity,
    AwsManagedPolicy,
    CredentialReportEntity,
    GroupEntity,
    IamStore,
    InstanceProfileEntity,
    ManagedPolicyEntity,
    MFADeviceEntity,
    OIDCProvider,
    RoleEntity,
    SAMLProvider,
    ServerCertificateEntity,
    UserEntity,
    iam_stores,
)
from localstack.services.iam.policy_validation import IAMPolicyDocumentValidator
from localstack.services.iam.resources.policy_simulator import (
    BasicIAMPolicySimulator,
    IAMPolicySimulator,
)
from localstack.services.iam.resources.service_linked_roles import SERVICE_LINKED_ROLES
from localstack.services.iam.utils import generate_iam_identifier
from localstack.services.plugins import ServiceLifecycleHook
from localstack.state import StateVisitor
from localstack.utils.aws.arns import ARN_PARTITION_REGEX, get_partition, parse_arn
from localstack.utils.aws.request_context import extract_access_key_id_from_auth_header
from localstack.utils.collections import PaginatedList

LOG = logging.getLogger(__name__)

SERVICE_LINKED_ROLE_PATH_PREFIX = "/aws-service-role"

POLICY_ARN_REGEX = re.compile(r"arn:[^:]+:iam::(?:\d{12}|aws):policy/.*")

CREDENTIAL_ID_REGEX = re.compile(r"^\w+$")

# Version ID format: v1, v2, etc. (AWS also accepts v1.2.abc style but we use simple v<n>)
VERSION_ID_REGEX = re.compile(r"^v[1-9][0-9]*(\.[A-Za-z0-9-]*)?$")

# Tag key regex pattern (from AWS documentation)
TAG_KEY_REGEX = re.compile(r"^[\w\s_.:/=+\-@]+$")

# AWS managed policy ARN regex
AWS_MANAGED_POLICY_ARN_REGEX = re.compile(rf"{ARN_PARTITION_REGEX}:iam::aws:policy/")

# Regex to normalize any AWS managed policy ARN to the "aws" partition for index lookup
_AWS_MANAGED_ARN_NORMALIZE_RE = re.compile(r"^arn:[^:]+:iam::aws:policy/")

# Maximum versions per policy
MAX_POLICY_VERSIONS = 5

# Maximum tags per policy
MAX_POLICY_TAGS = 50

# Maximum access keys per user
LIMIT_ACCESS_KEYS_PER_USER = 2

T = TypeVar("T")


class ValidationError(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("ValidationError", message, 400, True)


class ValidationListError(ValidationError):
    def __init__(self, validation_errors: list[str]):
        message = f"{len(validation_errors)} validation error{'s' if len(validation_errors) > 1 else ''} detected: {'; '.join(validation_errors)}"
        super().__init__(message)


class AccessDeniedError(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("AccessDenied", message, 403, True)


def get_iam_backend(context: RequestContext) -> IAMBackend:
    return iam_backends[context.account_id][context.partition]


class IamProvider(IamApi, ServiceLifecycleHook):
    policy_simulator: IAMPolicySimulator
    _policy_lock: threading.Lock
    _role_lock: threading.Lock
    _group_lock: threading.Lock
    _user_lock: threading.Lock
    _instance_profile_lock: threading.Lock
    _aws_managed_policy_cache: dict[str, ManagedPolicyEntity] | None

    def __init__(self):
        apply_iam_patches()
        self.policy_simulator = BasicIAMPolicySimulator()
        self._policy_lock = threading.Lock()
        self._role_lock = threading.Lock()
        self._group_lock = threading.Lock()
        self._user_lock = threading.Lock()
        self._instance_profile_lock = threading.Lock()
        self._aws_managed_policy_cache = None

    def on_after_init(self):
        self._aws_managed_policy_cache = self._build_aws_managed_policy_cache()

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(iam_backends)
        visitor.visit(iam_stores)

    @handler("CreateRole")
    def create_role(
        self,
        context: RequestContext,
        role_name: roleNameType,
        assume_role_policy_document: policyDocumentType,
        path: pathType | None = None,
        description: roleDescriptionType | None = None,
        max_session_duration: roleMaxSessionDurationType | None = None,
        permissions_boundary: arnType | None = None,
        tags: tagListType | None = None,
        **kwargs,
    ) -> CreateRoleResponse:
        store = self._get_store(context)

        # Validate trust policy
        self._validate_trust_policy(assume_role_policy_document)

        # Validate tags
        self._validate_tags(tags, case_sensitive=False)

        # Validate permissions boundary if provided
        if permissions_boundary:
            self._validate_permissions_boundary(context, permissions_boundary)

        with self._role_lock:
            # Check if role already exists
            if role_name in store.ROLES:
                raise EntityAlreadyExistsException(f"Role with name {role_name} already exists.")

            # Generate role ID and ARN
            role_id = self._generate_role_id(context, tags)
            path = path or "/"
            role_arn = self._build_role_arn(context, path, role_name)

            # Build the Role object
            role = Role(
                Path=path,
                RoleName=role_name,
                RoleId=role_id,
                Arn=role_arn,
                CreateDate=datetime.now(tz=UTC),
                # always quote policies
                AssumeRolePolicyDocument=quote(assume_role_policy_document),
                MaxSessionDuration=max_session_duration or 3600,
                RoleLastUsed=RoleLastUsed(),
            )

            if description:
                role["Description"] = description
            if tags:
                role["Tags"] = tags
            if permissions_boundary:
                role["PermissionsBoundary"] = AttachedPermissionsBoundary(
                    PermissionsBoundaryType="Policy",  # noqa the actual types don't have the right values
                    PermissionsBoundaryArn=permissions_boundary,
                )

            # Create role entity and store
            role_entity = RoleEntity(role=role)
            store.ROLES[role_name] = role_entity

            response_role = Role(role)

        # CreateRole response doesn't include some attributes
        response_role.pop("Description", None)
        response_role.pop("MaxSessionDuration", None)
        response_role.pop("RoleLastUsed", None)
        return CreateRoleResponse(Role=response_role)

    def _validate_permissions_boundary(
        self, context: RequestContext, permissions_boundary: str
    ) -> None:
        """Validate that a permissions boundary ARN is valid and exists."""
        # Check ARN format - must be a policy ARN
        if ":policy/" not in permissions_boundary:
            raise InvalidInputException(f"ARN {permissions_boundary} is not valid.")

        if self._is_managed_policy(permissions_boundary):
            # Validate against the static AWS managed policy index
            normalized_arn = self._normalize_aws_managed_arn(permissions_boundary)
            if normalized_arn not in self._aws_managed_policy_cache:
                raise NoSuchEntityException(
                    f"Scope ARN: {permissions_boundary} does not exist or is not attachable."
                )
        else:
            # Customer-managed: must exist in the store
            store = self._get_store(context)
            if permissions_boundary not in store.MANAGED_POLICIES:
                raise NoSuchEntityException(
                    f"Scope ARN: {permissions_boundary} does not exist or is not attachable."
                )

    def get_role(
        self, context: RequestContext, role_name: roleNameType, **kwargs
    ) -> GetRoleResponse:
        store = self._get_store(context)
        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)
            # Return a copy of the role
            role = Role(role_entity.role)
        return GetRoleResponse(Role=role)

    def delete_role(self, context: RequestContext, role_name: roleNameType, **kwargs) -> None:
        store = self._get_store(context)

        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)

            # Check if role has attached managed policies
            if role_entity.attached_policy_arns:
                raise DeleteConflictException(
                    "Cannot delete entity, must detach all policies first."
                )

            # Check if role has inline policies
            if role_entity.inline_policies:
                raise DeleteConflictException("Cannot delete entity, must delete policies first.")

            if self._get_profiles_for_role(store, role_name):
                raise DeleteConflictException(
                    "Cannot delete entity, must remove roles from instance profile first."
                )

            # Delete the role from native store
            del store.ROLES[role_name]

    def list_roles(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListRolesResponse:
        store = self._get_store(context)

        def _filter(role: Role) -> bool:
            if path_prefix:
                return role.get("Path", "/").startswith(path_prefix)
            return True

        def _map_to_response(role_entity: RoleEntity) -> Role:
            role = role_entity.role
            list_role = Role(
                Path=role["Path"],
                RoleName=role["RoleName"],
                RoleId=role["RoleId"],
                Arn=role["Arn"],
                CreateDate=role["CreateDate"],
                AssumeRolePolicyDocument=role["AssumeRolePolicyDocument"],
                MaxSessionDuration=role["MaxSessionDuration"],
            )
            if description := role.get("Description"):
                list_role["Description"] = description
            return list_role

        # Sort roles by RoleName (case-insensitive, as AWS does)
        with self._role_lock:
            roles = list(store.ROLES.values())
        # TODO find out if roles really are sorted
        sorted_roles = sorted(roles, key=lambda e: e.role.get("RoleName", "").lower())

        paginated_list = PaginatedList([_map_to_response(e) for e in sorted_roles])

        def _token_generator(role: Role) -> str:
            return role.get("RoleName")

        # Decode marker if provided (markers are base64-encoded)
        if marker:
            marker = base64.b64decode(marker).decode("utf-8")

        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator,
            next_token=marker,
            page_size=max_items or 100,
            filter_function=_filter,
        )

        if next_marker:
            # Encode the marker as base64 to make it opaque
            next_marker = base64.b64encode(next_marker.encode("utf-8")).decode("utf-8")
            return ListRolesResponse(Roles=result, IsTruncated=True, Marker=next_marker)
        else:
            return ListRolesResponse(Roles=result, IsTruncated=False)

    def update_role(
        self,
        context: RequestContext,
        role_name: roleNameType,
        description: roleDescriptionType = None,
        max_session_duration: roleMaxSessionDurationType = None,
        **kwargs,
    ) -> UpdateRoleResponse:
        store = self._get_store(context)
        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)

            # Only update fields that are explicitly provided
            if description is not None:
                role_entity.role["Description"] = description
            if max_session_duration is not None:
                role_entity.role["MaxSessionDuration"] = max_session_duration

        return UpdateRoleResponse()

    def update_role_description(
        self,
        context: RequestContext,
        role_name: roleNameType,
        description: roleDescriptionType,
        **kwargs,
    ) -> UpdateRoleDescriptionResponse:
        store = self._get_store(context)
        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)
            role_entity.role["Description"] = description
            # Return role without MaxSessionDuration and RoleLastUsed (AWS behavior)
            role = Role(role_entity.role)
            role.pop("MaxSessionDuration", None)
            role.pop("RoleLastUsed", None)

        return UpdateRoleDescriptionResponse(Role=role)

    def update_assume_role_policy(
        self,
        context: RequestContext,
        role_name: roleNameType,
        policy_document: policyDocumentType,
        **kwargs,
    ) -> None:
        # Validate the trust policy
        self._validate_trust_policy(policy_document)

        store = self._get_store(context)
        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)
            role_entity.role["AssumeRolePolicyDocument"] = policy_document

    # ------------------------------ Role Tag Operations ------------------------------ #

    def tag_role(
        self,
        context: RequestContext,
        role_name: roleNameType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        self._validate_tags(tags, case_sensitive=False)

        store = self._get_store(context)
        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)

            # Initialize tags if not present
            if "Tags" not in role_entity.role or role_entity.role["Tags"] is None:
                role_entity.role["Tags"] = []

            # Merge tags - update existing keys, add new ones, case-insensitive
            existing_keys = {
                tag["Key"].lower(): i for i, tag in enumerate(role_entity.role["Tags"])
            }
            for tag in tags:
                key = tag["Key"].lower()
                if key in existing_keys:
                    role_entity.role["Tags"][existing_keys[key]] = tag
                else:
                    role_entity.role["Tags"].append(tag)

    def untag_role(
        self,
        context: RequestContext,
        role_name: roleNameType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        self._validate_tag_keys(tag_keys)

        store = self._get_store(context)
        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)

            if "Tags" in role_entity.role and role_entity.role["Tags"]:
                # Remove tags with matching keys (case-sensitive)
                tag_keys_set = {key.lower() for key in tag_keys}
                role_entity.role["Tags"] = [
                    tag
                    for tag in role_entity.role["Tags"]
                    if tag["Key"].lower() not in tag_keys_set
                ]

    def list_role_tags(
        self,
        context: RequestContext,
        role_name: roleNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListRoleTagsResponse:
        store = self._get_store(context)
        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)
            tags = list(role_entity.role.get("Tags") or [])

        # Sort alphabetically by key, then by key length
        tags.sort(key=lambda k: k["Key"])
        tags.sort(key=lambda k: len(k["Key"]))

        paginated_list = PaginatedList(tags)

        def _token_generator(tag: Tag) -> str:
            return tag.get("Key")

        # base64 encode/decode to avoid plaintext tag as marker
        if marker:
            marker = base64.b64decode(marker).decode("utf-8")

        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator, next_token=marker, page_size=max_items or 100
        )

        if next_marker:
            next_marker = base64.b64encode(next_marker.encode("utf-8")).decode("utf-8")
            return ListRoleTagsResponse(Tags=result, IsTruncated=True, Marker=next_marker)
        else:
            return ListRoleTagsResponse(Tags=result, IsTruncated=False)

    # ------------------------------ Role Inline Policy Operations ------------------------------ #

    def put_role_policy(
        self,
        context: RequestContext,
        role_name: roleNameType,
        policy_name: policyNameType,
        policy_document: policyDocumentType,
        **kwargs,
    ) -> None:
        # Validate policy document
        validator = IAMPolicyDocumentValidator(policy_document)
        validator.validate()

        store = self._get_store(context)
        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)
            # always quote policies
            role_entity.inline_policies[policy_name] = quote(policy_document)

    def get_role_policy(
        self,
        context: RequestContext,
        role_name: roleNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> GetRolePolicyResponse:
        store = self._get_store(context)
        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)

            policy_document = role_entity.inline_policies.get(policy_name)
            if policy_document is None:
                raise NoSuchEntityException(
                    f"The role policy with name {policy_name} cannot be found."
                )

        return GetRolePolicyResponse(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=policy_document,
        )

    def list_role_policies(
        self,
        context: RequestContext,
        role_name: roleNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListRolePoliciesResponse:
        store = self._get_store(context)
        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)
            policy_names = sorted(role_entity.inline_policies.keys())

        paginated_list = PaginatedList(policy_names)

        def _token_generator(name: str) -> str:
            return name

        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator,
            next_token=marker,
            page_size=max_items or 100,
        )

        if next_marker:
            return ListRolePoliciesResponse(
                PolicyNames=result, IsTruncated=True, Marker=next_marker
            )
        else:
            return ListRolePoliciesResponse(PolicyNames=result, IsTruncated=False)

    def delete_role_policy(
        self,
        context: RequestContext,
        role_name: roleNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> None:
        store = self._get_store(context)
        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)

            if policy_name not in role_entity.inline_policies:
                raise NoSuchEntityException(
                    f"The role policy with name {policy_name} cannot be found."
                )

            del role_entity.inline_policies[policy_name]

    @handler("SimulatePrincipalPolicy", expand=False)
    def simulate_principal_policy(
        self,
        context: RequestContext,
        request: SimulatePrincipalPolicyRequest,
        **kwargs,
    ) -> SimulatePolicyResponse:
        return self.policy_simulator.simulate_principal_policy(context, request)

    # ------------------------------ Managed Policy Operations ------------------------------ #

    def _get_store(self, context: RequestContext) -> IamStore:
        """Get the IAM store for the current account and region."""
        return iam_stores[context.account_id][context.region]

    def _generate_policy_id(self) -> str:
        """Generate a policy ID: 'A' followed by 20 random alphanumeric characters."""
        return "A" + "".join(random.choices(string.ascii_uppercase + string.digits, k=20))

    def _build_policy_arn(self, context: RequestContext, path: str, policy_name: str) -> str:
        """Build the ARN for a managed policy."""
        partition = get_partition(context.region)
        # Path has a prefix like /my/path/
        return f"arn:{partition}:iam::{context.account_id}:policy{path}{policy_name}"

    def _validate_tags(self, tags: tagListType | None, case_sensitive: bool = True) -> None:
        """
        Validate tags according to AWS rules.

        :param tags: Tags to validate
        :param case_sensitive: Whether the operation supports saving tags with case sensitivity, or if tags are overwritten
            even with different casing
        """
        if not tags:
            return

        errors = []
        if len(tags) > MAX_POLICY_TAGS:
            errors.append(
                "Value at 'tags' failed to satisfy constraint: Member must have length less than or equal to 50"
            )

        # early return
        if errors:
            raise ValidationListError(errors)

        seen_keys = set()
        for tag in tags:
            key = tag.get("Key", "")
            value = tag.get("Value", "")
            # This is sadly very inconsistent over the IAM API
            if not case_sensitive:
                key = key.lower()

            # Check for duplicate keys (case-sensitive)
            if key in seen_keys:
                error_message = "Duplicate tag keys found."
                if not case_sensitive:
                    error_message += " Please note that Tag keys are case insensitive."
                raise InvalidInputException(error_message)
            seen_keys.add(key)

            # Key length
            if len(key) > 128:
                errors.append(
                    f"Value at 'tags.{len(seen_keys)}.member.key' "
                    f"failed to satisfy constraint: Member must have length less than or equal to 128"
                )

            # Value length
            if len(value) > 256:
                errors.append(
                    f"Value at 'tags.{len(seen_keys)}.member.value' "
                    f"failed to satisfy constraint: Member must have length less than or equal to 256"
                )

            # Key format validation
            if not TAG_KEY_REGEX.match(key):
                errors.append(
                    f"Value at 'tags.{len(seen_keys)}.member.key' "
                    f"failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{{L}}\\p{{Z}}\\p{{N}}_.:/=+\\-@]+"
                )
        if errors:
            raise ValidationListError(errors)

    def _validate_tag_keys(self, tag_keys: tagKeyListType | None) -> None:
        """Validate tag keys for untag operations."""
        if not tag_keys:
            return

        errors = []
        if len(tag_keys) > MAX_POLICY_TAGS:
            errors.append(
                "Value at 'tagKeys' "
                "failed to satisfy constraint: Member must have length less than or equal to 50"
            )

        for i, key in enumerate(tag_keys):
            if not key or len(key) > 128 or not TAG_KEY_REGEX.match(key):
                errors.append(
                    "Value at 'tagKeys' failed to satisfy constraint: Member must satisfy constraint: [Member must have length less than or equal to 128, Member must have length greater than or equal to 1, Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+, Member must not be null]"
                )
        if errors:
            raise ValidationListError(errors)

    def _get_custom_id_from_tags(self, tags: list[Tag]) -> str | None:
        """
        Check an IAM tag list for a custom id tag, and return the value if present.

        :param tags: List of tags
        :return: Custom Id or None if not present
        """
        if not tags:
            return
        for tag in tags:
            if tag["Key"] == TAG_KEY_CUSTOM_ID:
                return tag["Value"]
        return None

    def _get_policy_entity(self, store: IamStore, policy_arn: str) -> ManagedPolicyEntity:
        """Gets the policy entity and raises the right exception if not found."""
        entity = store.MANAGED_POLICIES.get(policy_arn)
        if not entity:
            raise NoSuchEntityException(f"Policy {policy_arn} was not found.")
        return entity

    def _is_managed_policy(self, policy_arn: str) -> bool:
        """
        Check if a policy arn is for an AWS managed policy
        :param policy_arn: Policy ARN to check
        """
        return bool(AWS_MANAGED_POLICY_ARN_REGEX.match(policy_arn))

    def _get_aws_managed_policy(self, store: IamStore, policy_arn: str) -> ManagedPolicyEntity:
        normalized_arn = self._normalize_aws_managed_arn(policy_arn)
        policy_entity = self._aws_managed_policy_cache.get(normalized_arn)
        if not policy_entity:
            raise NoSuchEntityException(f"Policy {policy_arn} was not found.")
        policy_entity = copy.copy(policy_entity)
        policy_entity.policy = Policy(policy_entity.policy)
        managed_policy_store_data = store.AWS_MANAGED_POLICIES.get(policy_arn)
        policy_entity.policy["AttachmentCount"] = (
            managed_policy_store_data.attachment_count if managed_policy_store_data else 0
        )
        # set the right partitions ARN in the return entity
        policy_entity.policy["Arn"] = policy_arn
        return policy_entity

    def _build_aws_managed_policy_cache(self) -> dict[str, ManagedPolicyEntity]:
        """Parse the static managed-policy dataset and build an ARN-keyed lookup dict.

        Keys are normalized ARNs of the form ``arn:aws:iam::aws:policy<Path><Name>``.
        Each value is the raw data dict augmented with the ``PolicyName`` key.
        """
        with open(
            os.path.join(os.path.dirname(__file__), "resources/aws_managed_policies.json")
        ) as f:
            data: dict[str, dict] = json.load(f)
        index: dict[str, ManagedPolicyEntity] = {}
        for name, policy_data in data.items():
            path: str = policy_data["Path"]
            arn = f"arn:aws:iam::aws:policy{path}{name}"
            policy = Policy(
                PolicyName=name,
                PolicyId=self._generate_aws_managed_policy_id(name),
                Arn=arn,
                Path=path,
                DefaultVersionId=policy_data["DefaultVersionId"],
                AttachmentCount=0,
                PermissionsBoundaryUsageCount=0,
                IsAttachable=True,
                CreateDate=datetime.fromisoformat(policy_data["CreateDate"]),
                UpdateDate=datetime.fromisoformat(policy_data["UpdateDate"]),
                Tags=[],
            )
            versions = {
                policy_data["DefaultVersionId"]: PolicyVersion(
                    VersionId=policy_data["DefaultVersionId"],
                    Document=quote(json.dumps(policy_data["Document"])),
                    IsDefaultVersion=True,
                    CreateDate=datetime.fromisoformat(policy_data["UpdateDate"]),
                )
            }
            index[arn] = ManagedPolicyEntity(
                policy=policy,
                versions=versions,
            )
        return index

    def _normalize_aws_managed_arn(self, arn: str) -> str:
        """Return the canonical ``arn:aws:iam::aws:policy/...`` form of an AWS managed policy ARN.

        This handles China (aws-cn) and GovCloud (aws-us-gov) partitions transparently.
        TODO we might want to properly store the policies by partition in the future.
        """
        return _AWS_MANAGED_ARN_NORMALIZE_RE.sub("arn:aws:iam::aws:policy/", arn)

    def _generate_aws_managed_policy_id(self, name: str) -> str:
        """Generate a deterministic, stable PolicyId for an AWS managed policy.

        The format mirrors real AWS IDs (``ANPA`` + 17 upper-hex chars).  The value
        is derived from a SHA-256 hash of the policy name so it is consistent across
        restarts without needing to be persisted.
        """
        hash_hex = hashlib.sha256(name.encode()).hexdigest()[:17].upper()
        return f"ANPA{hash_hex}"

    def _attach_policy(self, store: IamStore, policy_arn: str) -> None:
        """

        :param store:
        :param policy_arn:
        :return:
        """
        is_aws_managed = self._is_managed_policy(policy_arn)
        if is_aws_managed:
            # Track attachment count for AWS managed policies
            if policy_arn not in store.AWS_MANAGED_POLICIES:
                store.AWS_MANAGED_POLICIES[policy_arn] = AwsManagedPolicy()
            store.AWS_MANAGED_POLICIES[policy_arn].attachment_count += 1
        else:
            # Update AttachmentCount for customer-managed policies
            policy_entity = store.MANAGED_POLICIES[policy_arn]
            policy_entity.policy["AttachmentCount"] += 1

    def _detach_policy(self, store: IamStore, policy_arn: str) -> None:
        is_aws_managed = self._is_managed_policy(policy_arn)
        if is_aws_managed:
            # Decrement attachment count for AWS managed policies
            if policy_arn in store.AWS_MANAGED_POLICIES:
                store.AWS_MANAGED_POLICIES[policy_arn].attachment_count -= 1
                if store.AWS_MANAGED_POLICIES[policy_arn].attachment_count <= 0:
                    del store.AWS_MANAGED_POLICIES[policy_arn]
        else:
            # Update AttachmentCount for customer-managed policies
            if policy_arn in store.MANAGED_POLICIES:
                policy_entity = store.MANAGED_POLICIES[policy_arn]
                policy_entity.policy["AttachmentCount"] -= 1

    def _assert_policy_exists(self, store: IamStore, policy_arn: str) -> None:
        is_aws_managed = self._is_managed_policy(policy_arn)
        errored = False
        if is_aws_managed:
            # Validate that the AWS managed policy actually exists in the static index
            normalized_arn = self._normalize_aws_managed_arn(policy_arn)
            if normalized_arn not in self._aws_managed_policy_cache:
                errored = True
        else:
            # Customer-managed: must exist in the store
            if policy_arn not in store.MANAGED_POLICIES:
                errored = True
        if errored:
            raise NoSuchEntityException(f"Policy {policy_arn} does not exist or is not attachable.")

    # ------------------------------ Role Helper Methods ------------------------------ #

    def _generate_role_id(self, context: RequestContext, tags: list[Tag] | None = None) -> str:
        """Generate a role ID: AROA + 17 random chars, or use custom ID from tags."""
        custom_id = self._get_custom_id_from_tags(tags)
        if custom_id:
            return custom_id
        return generate_iam_identifier(context.account_id, prefix="AROA", total_length=21)

    def _build_role_arn(
        self, context: RequestContext, path: str, role_name: str, is_service_linked: bool = False
    ) -> str:
        """Build the ARN for a role."""
        partition = get_partition(context.region)
        return f"arn:{partition}:iam::{context.account_id}:role{path}{role_name}"

    def _get_role_entity(self, store: IamStore, role_name: str) -> RoleEntity:
        """Gets the role entity and raises the right exception if not found."""
        entity = store.ROLES.get(role_name)
        if not entity:
            raise NoSuchEntityException(f"The role with name {role_name} cannot be found.")
        return entity

    def _validate_trust_policy(self, policy_document: str) -> dict:
        """Validate and parse a trust policy document."""
        try:
            policy = json.loads(policy_document)
        except json.JSONDecodeError:
            raise MalformedPolicyDocumentException("This policy contains invalid Json")

        # Validate trust policy structure (basic validation)
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            # Check for Resource field (not allowed in trust policies)
            if "Resource" in statement:
                raise MalformedPolicyDocumentException("Has prohibited field Resource")
            # Check for valid STS actions
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            valid_sts_actions = {
                "sts:AssumeRole",
                "sts:AssumeRoleWithSAML",
                "sts:AssumeRoleWithWebIdentity",
                "sts:TagSession",
                "sts:SetSourceIdentity",
            }
            for action in actions:
                if action != "*" and action not in valid_sts_actions:
                    raise MalformedPolicyDocumentException(
                        "AssumeRole policy may only specify STS AssumeRole actions."
                    )

        return policy

    # ------------------------------ User Helper Methods ------------------------------ #

    def _generate_user_id(self, context: RequestContext, tags: list[Tag] | None = None) -> str:
        """Generate a user ID: AIDA + 17 random chars, or use custom ID from tags."""
        custom_id = self._get_custom_id_from_tags(tags)
        if custom_id:
            return custom_id
        return generate_iam_identifier(context.account_id, prefix="AIDA", total_length=21)

    def _build_user_arn(self, context: RequestContext, path: str, user_name: str) -> str:
        """Build the ARN for a user."""
        partition = get_partition(context.region)
        return f"arn:{partition}:iam::{context.account_id}:user{path}{user_name}"

    def _get_user_entity(self, store: IamStore, user_name: str) -> UserEntity:
        """Gets the user entity and raises the right exception if not found."""
        entity = store.USERS.get(user_name)
        if not entity:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")
        return entity

    def create_policy(
        self,
        context: RequestContext,
        policy_name: policyNameType,
        policy_document: policyDocumentType,
        path: policyPathType = None,
        description: policyDescriptionType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> CreatePolicyResponse:
        # Validate policy document
        validator = IAMPolicyDocumentValidator(policy_document)
        validator.validate()

        # Validate tags
        self._validate_tags(tags)

        store = self._get_store(context)
        path = path or "/"

        with self._policy_lock:
            # Build ARN and check for duplicates
            policy_arn = self._build_policy_arn(context, path, policy_name)
            if policy_arn in store.MANAGED_POLICIES:
                raise EntityAlreadyExistsException(
                    f"A policy called {policy_name} already exists. Duplicate names are not allowed."
                )

            # Generate IDs and timestamps
            policy_id = self._get_custom_id_from_tags(tags) or self._generate_policy_id()
            now = datetime.now(UTC)

            # Create the initial version (v1)
            version = PolicyVersion(
                # always quote policies
                Document=quote(policy_document),
                VersionId="v1",
                IsDefaultVersion=True,
                CreateDate=now,
            )

            # Create the policy for storage (with Description if provided)
            policy = Policy(
                PolicyName=policy_name,
                PolicyId=policy_id,
                Arn=policy_arn,
                Path=path,
                DefaultVersionId="v1",
                AttachmentCount=0,
                PermissionsBoundaryUsageCount=0,
                IsAttachable=True,
                CreateDate=now,
                UpdateDate=now,
                Tags=tags or [],
            )
            # Store Description in the policy for get_policy to return
            if description:
                policy["Description"] = description

            # Store the policy entity
            policy_entity = ManagedPolicyEntity(
                policy=policy,
                versions={"v1": version},
                next_version_num=2,
            )
            store.MANAGED_POLICIES[policy_arn] = policy_entity

        # AWS create_policy response does NOT include Description (get_policy does)
        response_policy = Policy(policy)
        response_policy.pop("Description", None)
        if not tags:
            response_policy.pop("Tags", None)

        return CreatePolicyResponse(Policy=response_policy)

    def get_policy(
        self, context: RequestContext, policy_arn: arnType, **kwargs
    ) -> GetPolicyResponse:
        store = self._get_store(context)

        if self._is_managed_policy(policy_arn):
            policy = self._get_aws_managed_policy(store, policy_arn).policy
            return GetPolicyResponse(Policy=policy)
        with self._policy_lock:
            policy_entity = self._get_policy_entity(store, policy_arn)

            # Return a copy of the policy with current tags (AWS returns empty list if no tags)
            policy = dict(policy_entity.policy)

        return GetPolicyResponse(Policy=policy)

    def delete_policy(self, context: RequestContext, policy_arn: arnType, **kwargs) -> None:
        if parse_arn(policy_arn)["account"] != context.account_id:
            raise AccessDeniedError("Cannot delete policies outside your own account.")
        # TODO test deletion when attached to principals
        store = self._get_store(context)
        with self._policy_lock:
            policy_entity = self._get_policy_entity(store, policy_arn)
            if policy_entity.policy.get("AttachmentCount") > 0:
                raise DeleteConflictException("Cannot delete a policy attached to entities.")
            store.MANAGED_POLICIES.pop(policy_arn)

    def list_policies(
        self,
        context: RequestContext,
        scope: policyScopeType = None,
        only_attached: booleanType = None,
        path_prefix: pathPrefixType = None,
        policy_usage_filter: PolicyUsageType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListPoliciesResponse:
        store = self._get_store(context)

        # Collect customer-managed ("Local") policies, sorted alphabetically
        local_policies: list[Policy] = []
        if scope != "AWS":
            for entity in store.MANAGED_POLICIES.values():
                policy = Policy(entity.policy)
                if not policy.get("Tags"):
                    policy.pop("Tags", None)
                local_policies.append(policy)
            local_policies.sort(key=lambda p: p.get("PolicyName", ""))

        # Collect AWS-managed policies from the static index, sorted alphabetically
        aws_policies: list[Policy] = []
        if scope != "Local":
            for normalized_arn, entry in self._aws_managed_policy_cache.items():
                policy_arn = normalized_arn.replace("arn:aws:", f"arn:{context.partition}:")
                aws_mp = store.AWS_MANAGED_POLICIES.get(policy_arn)
                attachment_count = aws_mp.attachment_count if aws_mp else 0
                policy = Policy(entry.policy)
                policy["Arn"] = policy_arn
                policy["AttachmentCount"] = attachment_count
                # list_policies does not return Tags (unlike get_policy)
                if not policy.get("Tags"):
                    policy.pop("Tags", None)
                aws_policies.append(policy)
            aws_policies.sort(key=lambda p: p.get("PolicyName", ""))

        # For Scope=AWS or Scope=Local return a single sorted list.
        # For Scope=All (default), place customer-managed policies first so they always appear
        # on the first page regardless of alphabetical position relative to AWS managed names.
        if scope == "AWS":
            all_policies = aws_policies
        elif scope == "Local":
            all_policies = local_policies
        else:
            all_policies = local_policies + aws_policies

        def _filter(policy: Policy) -> bool:
            if path_prefix and not policy.get("Path", "/").startswith(path_prefix):
                return False
            if only_attached and policy.get("AttachmentCount", 0) == 0:
                return False
            return True

        def _token_generator(policy: Policy) -> str:
            return policy.get("PolicyName", "")

        paginated_list = PaginatedList(all_policies)
        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator,
            next_token=marker,
            page_size=max_items or 100,
            filter_function=_filter,
        )

        if next_marker:
            return ListPoliciesResponse(Policies=result, IsTruncated=True, Marker=next_marker)
        else:
            return ListPoliciesResponse(Policies=result, IsTruncated=False)

    def list_entities_for_policy(
        self,
        context: RequestContext,
        policy_arn: arnType,
        entity_filter: EntityType | None = None,
        path_prefix: pathType | None = None,
        policy_usage_filter: PolicyUsageType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListEntitiesForPolicyResponse:
        store = self._get_store(context)

        # Validate policy exists
        self._assert_policy_exists(store, policy_arn)

        # LocalManagedPolicy and AWSManagedPolicy filters always return empty in AWS for some reason
        if entity_filter in (EntityType.LocalManagedPolicy, EntityType.AWSManagedPolicy):
            return ListEntitiesForPolicyResponse(
                PolicyGroups=[], PolicyUsers=[], PolicyRoles=[], IsTruncated=False
            )

        # Determine which entity types to search based on entity filter
        search_users = entity_filter in (None, EntityType.User)
        search_roles = entity_filter in (None, EntityType.Role)
        search_groups = entity_filter in (None, EntityType.Group)

        # Default policy_usage_filter to PermissionsPolicy if not specified
        check_permissions_policy = policy_usage_filter in (None, PolicyUsageType.PermissionsPolicy)
        check_permissions_boundary = policy_usage_filter == PolicyUsageType.PermissionsBoundary

        policy_users: list[PolicyUser] = []
        policy_roles: list[PolicyRole] = []
        policy_groups: list[PolicyGroup] = []

        # Search users
        if search_users:
            with self._user_lock:
                for user_entity in store.USERS.values():
                    user = user_entity.user
                    user_path = user.get("Path", "/")
                    if path_prefix and not user_path.startswith(path_prefix):
                        continue

                    matched = False
                    if check_permissions_policy and policy_arn in user_entity.attached_policy_arns:
                        matched = True
                    if check_permissions_boundary:
                        pb = user.get("PermissionsBoundary", {})
                        if pb.get("PermissionsBoundaryArn") == policy_arn:
                            matched = True

                    if matched:
                        policy_users.append(
                            PolicyUser(UserName=user["UserName"], UserId=user["UserId"])
                        )

        # Search roles
        if search_roles:
            with self._role_lock:
                for role_entity in store.ROLES.values():
                    role = role_entity.role
                    role_path = role.get("Path", "/")
                    if path_prefix and not role_path.startswith(path_prefix):
                        continue

                    matched = False
                    if check_permissions_policy and policy_arn in role_entity.attached_policy_arns:
                        matched = True
                    if check_permissions_boundary:
                        pb = role.get("PermissionsBoundary", {})
                        if pb.get("PermissionsBoundaryArn") == policy_arn:
                            matched = True

                    if matched:
                        policy_roles.append(
                            PolicyRole(RoleName=role["RoleName"], RoleId=role["RoleId"])
                        )

        # Search groups (groups don't support PermissionsBoundary)
        if search_groups and check_permissions_policy:
            with self._group_lock:
                for group_entity in store.GROUPS.values():
                    group = group_entity.group
                    group_path = group.get("Path", "/")
                    if path_prefix and not group_path.startswith(path_prefix):
                        continue

                    if policy_arn in group_entity.attached_policy_arns:
                        policy_groups.append(
                            PolicyGroup(GroupName=group["GroupName"], GroupId=group["GroupId"])
                        )

        return ListEntitiesForPolicyResponse(
            PolicyUsers=policy_users,
            PolicyRoles=policy_roles,
            PolicyGroups=policy_groups,
            IsTruncated=False,
        )

    # ------------------------------ Policy Version Operations ------------------------------ #

    def create_policy_version(
        self,
        context: RequestContext,
        policy_arn: arnType,
        policy_document: policyDocumentType,
        set_as_default: booleanType = None,
        **kwargs,
    ) -> CreatePolicyVersionResponse:
        # Validate policy document
        validator = IAMPolicyDocumentValidator(policy_document)
        validator.validate()

        store = self._get_store(context)
        with self._policy_lock:
            policy_entity = self._get_policy_entity(store, policy_arn)

            # Check version limit
            if len(policy_entity.versions) >= MAX_POLICY_VERSIONS:
                raise LimitExceededException(
                    f"A managed policy can have up to {MAX_POLICY_VERSIONS} versions. "
                    f"Before you create a new version, you must delete an existing version."
                )

            # Create new version
            version_id = f"v{policy_entity.next_version_num}"
            policy_entity.next_version_num += 1
            now = datetime.now(UTC)

            version = PolicyVersion(
                # always quote policies
                Document=quote(policy_document),
                VersionId=version_id,
                IsDefaultVersion=bool(set_as_default),
                CreateDate=now,
            )

            # If setting as default, update the old default
            if set_as_default:
                for v in policy_entity.versions.values():
                    v["IsDefaultVersion"] = False
                policy_entity.policy["DefaultVersionId"] = version_id
                policy_entity.policy["UpdateDate"] = now

            policy_entity.versions[version_id] = version

        # Return version without Document (AWS doesn't include it in create response)
        response_version = PolicyVersion(
            VersionId=version_id,
            IsDefaultVersion=bool(set_as_default),
            CreateDate=now,
        )

        return CreatePolicyVersionResponse(PolicyVersion=response_version)

    def get_policy_version(
        self,
        context: RequestContext,
        policy_arn: arnType,
        version_id: policyVersionIdType,
        **kwargs,
    ) -> GetPolicyVersionResponse:
        # Validate version ID format (AWS returns ValidationError for malformed IDs)
        if not VERSION_ID_REGEX.match(version_id):
            raise ValidationError(
                "1 validation error detected: Value at 'versionId' failed to satisfy constraint: "
                r"Member must satisfy regular expression pattern: v[1-9][0-9]*(\.[A-Za-z0-9-]*)?"
            )

        if self._is_managed_policy(policy_arn):
            normalized_arn = self._normalize_aws_managed_arn(policy_arn)
            entry = self._aws_managed_policy_cache.get(normalized_arn)
            if not entry:
                raise NoSuchEntityException(
                    f"Policy {policy_arn} version {version_id} does not exist or is not attachable."
                )
            version = entry.versions.get(version_id)
            # Only the current default version is available in the static dataset
            if not version:
                raise NoSuchEntityException(
                    f"Policy {policy_arn} version {version_id} does not exist or is not attachable."
                )
            version = PolicyVersion(version)
            return GetPolicyVersionResponse(PolicyVersion=version)

        store = self._get_store(context)
        with self._policy_lock:
            policy_entity = store.MANAGED_POLICIES.get(policy_arn)
            # For get/set/delete version: if policy doesn't exist, use version-style error message
            if not policy_entity:
                raise NoSuchEntityException(
                    f"Policy {policy_arn} version {version_id} does not exist or is not attachable."
                )

            version = policy_entity.versions.get(version_id)
            if not version:
                raise NoSuchEntityException(
                    f"Policy {policy_arn} version {version_id} does not exist or is not attachable."
                )

        return GetPolicyVersionResponse(PolicyVersion=version)

    def list_policy_versions(
        self,
        context: RequestContext,
        policy_arn: arnType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListPolicyVersionsResponse:
        store = self._get_store(context)
        with self._policy_lock:
            if self._is_managed_policy(policy_arn):
                policy_entity = self._get_aws_managed_policy(store, policy_arn)
            else:
                policy_entity = self._get_policy_entity(store, policy_arn)

            # Sort versions by version ID descending (most recent first)
            sorted_versions = sorted(
                policy_entity.versions.values(),
                key=lambda v: int(v["VersionId"][1:].split(".")[0]),
                reverse=True,
            )

            # Return versions without Document field
            versions = [
                PolicyVersion(
                    VersionId=v["VersionId"],
                    IsDefaultVersion=v.get("IsDefaultVersion", False),
                    CreateDate=v.get("CreateDate"),
                )
                for v in sorted_versions
            ]

        return ListPolicyVersionsResponse(Versions=versions, IsTruncated=False)

    def delete_policy_version(
        self,
        context: RequestContext,
        policy_arn: arnType,
        version_id: policyVersionIdType,
        **kwargs,
    ) -> None:
        if parse_arn(policy_arn)["account"] != context.account_id:
            raise AccessDeniedError(
                "Cannot delete policy versions for policies outside your own account."
            )
        store = self._get_store(context)
        with self._policy_lock:
            policy_entity = self._get_policy_entity(store, policy_arn)

            version = policy_entity.versions.get(version_id)
            if not version:
                raise NoSuchEntityException(
                    f"Policy {policy_arn} version {version_id} does not exist or is not attachable."
                )

            # Cannot delete the default version
            if version.get("IsDefaultVersion"):
                raise DeleteConflictException("Cannot delete the default version of a policy.")

            del policy_entity.versions[version_id]

    def set_default_policy_version(
        self,
        context: RequestContext,
        policy_arn: arnType,
        version_id: policyVersionIdType,
        **kwargs,
    ) -> None:
        # Validate version ID format
        if not VERSION_ID_REGEX.match(version_id):
            raise ValidationError(
                "1 validation error detected: Value at 'versionId' failed to satisfy constraint: "
                r"Member must satisfy regular expression pattern: v[1-9][0-9]*(\.[A-Za-z0-9-]*)?"
            )

        if parse_arn(policy_arn)["account"] != context.account_id:
            raise AccessDeniedError("Cannot update policies outside your own account.")

        store = self._get_store(context)
        with self._policy_lock:
            entity = store.MANAGED_POLICIES.get(policy_arn)
            # For get/set/delete version: if policy doesn't exist, use version-style error message
            if not entity:
                raise NoSuchEntityException(
                    f"Policy {policy_arn} version {version_id} does not exist or is not attachable."
                )

            version = entity.versions.get(version_id)
            if not version:
                raise NoSuchEntityException(
                    f"Policy {policy_arn} version {version_id} does not exist or is not attachable."
                )

            # Update IsDefaultVersion for all versions
            for v in entity.versions.values():
                v["IsDefaultVersion"] = False
            version["IsDefaultVersion"] = True

            # Update the policy
            entity.policy["DefaultVersionId"] = version_id
            entity.policy["UpdateDate"] = datetime.now(UTC)

    # ------------------------------ Policy Tag Operations ------------------------------ #

    def tag_policy(
        self,
        context: RequestContext,
        policy_arn: arnType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        self._validate_tags(tags)

        store = self._get_store(context)
        with self._policy_lock:
            policy_entity = self._get_policy_entity(store, policy_arn)

            # Merge tags - update existing keys, add new ones
            existing_keys = {tag["Key"]: i for i, tag in enumerate(policy_entity.policy["Tags"])}
            for tag in tags:
                key = tag["Key"]
                if key in existing_keys:
                    policy_entity.policy["Tags"][existing_keys[key]] = tag
                else:
                    policy_entity.policy["Tags"].append(tag)

    def untag_policy(
        self,
        context: RequestContext,
        policy_arn: arnType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        self._validate_tag_keys(tag_keys)

        store = self._get_store(context)
        with self._policy_lock:
            policy_entity = self._get_policy_entity(store, policy_arn)

            # Remove tags with matching keys (case-sensitive)
            tag_keys_set = set(tag_keys)
            policy_entity.policy["Tags"] = [
                tag for tag in policy_entity.policy["Tags"] if tag["Key"] not in tag_keys_set
            ]

    def list_policy_tags(
        self,
        context: RequestContext,
        policy_arn: arnType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListPolicyTagsResponse:
        store = self._get_store(context)
        with self._policy_lock:
            policy_entity = self._get_policy_entity(store, policy_arn)

            tags = list(policy_entity.policy.get("Tags") or [])
        # sort alphabetically
        tags.sort(key=lambda k: k["Key"])
        # then by length
        tags.sort(key=lambda k: len(k["Key"]))

        paginated_list = PaginatedList(tags)

        def _token_generator(tag: Tag) -> str:
            return tag.get("Key")

        # base64 encode/decode to avoid plaintext tag as marker
        if marker:
            marker = base64.b64decode(marker).decode("utf-8")

        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator, next_token=marker, page_size=max_items or 100
        )

        if next_marker:
            next_marker = base64.b64encode(next_marker.encode("utf-8")).decode("utf-8")
            return ListPolicyTagsResponse(Tags=result, IsTruncated=True, Marker=next_marker)
        else:
            return ListPolicyTagsResponse(Tags=result, IsTruncated=False)

    # ------------------------------ Group Operations ------------------------------ #

    def _get_group_entity(self, store: IamStore, group_name: str) -> GroupEntity:
        """Gets the group entity and raises the right exception if not found."""
        entity = store.GROUPS.get(group_name)
        if not entity:
            raise NoSuchEntityException(f"The group with name {group_name} cannot be found.")
        return entity

    def _generate_group_id(self, context: RequestContext) -> str:
        """Generate a group ID: AGPA + 17 random chars."""
        return generate_iam_identifier(context.account_id, prefix="AGPA", total_length=21)

    def _build_group_arn(self, context: RequestContext, path: str, group_name: str) -> str:
        """Build the ARN for a group."""
        partition = get_partition(context.region)
        # Path for ARN: /path/ becomes /path/ in the ARN resource portion
        if path == "/":
            return f"arn:{partition}:iam::{context.account_id}:group/{group_name}"
        else:
            # Remove leading slash for ARN construction
            path_part = path[1:] if path.startswith("/") else path
            return f"arn:{partition}:iam::{context.account_id}:group/{path_part}{group_name}"

    def create_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        path: pathType | None = None,
        **kwargs,
    ) -> CreateGroupResponse:
        store = self._get_store(context)
        path = path or "/"

        with self._group_lock:
            # Check for duplicate group
            if group_name in store.GROUPS:
                raise EntityAlreadyExistsException(f"Group with name {group_name} already exists.")

            # Generate group ID and ARN
            group_id = self._generate_group_id(context)
            group_arn = self._build_group_arn(context, path, group_name)

            # Build the Group object
            group = Group(
                Path=path,
                GroupName=group_name,
                GroupId=group_id,
                Arn=group_arn,
                CreateDate=datetime.now(tz=UTC),
            )

            # Create group entity and store
            group_entity = GroupEntity(group=group)
            store.GROUPS[group_name] = group_entity

        return CreateGroupResponse(Group=group)

    def get_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> GetGroupResponse:
        store = self._get_store(context)

        with self._group_lock:
            group_entity = self._get_group_entity(store, group_name)

            users = []
            for user_name in group_entity.member_user_names:
                if user := store.USERS.get(user_name):
                    users.append(user.user)

            return GetGroupResponse(
                Group=Group(group_entity.group),
                Users=users,
                IsTruncated=False,
            )

    def list_groups(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListGroupsResponse:
        store = self._get_store(context)

        def _filter(group: Group) -> bool:
            if path_prefix:
                return group.get("Path", "/").startswith(path_prefix)
            return True

        with self._group_lock:
            groups = [Group(e.group) for e in store.GROUPS.values()]

        # Filter and sort
        filtered_groups = [g for g in groups if _filter(g)]
        sorted_groups = sorted(filtered_groups, key=lambda g: g.get("GroupName", "").lower())

        # TODO: Add pagination support
        return ListGroupsResponse(Groups=sorted_groups, IsTruncated=False)

    def delete_group(self, context: RequestContext, group_name: groupNameType, **kwargs) -> None:
        store = self._get_store(context)

        with self._group_lock:
            group_entity = self._get_group_entity(store, group_name)

            # Check if group has attached policies
            if group_entity.attached_policy_arns:
                raise DeleteConflictException(
                    "Cannot delete entity, must detach all policies first."
                )

            # Check if group has inline policies
            if group_entity.inline_policies:
                raise DeleteConflictException("Cannot delete entity, must delete policies first.")

            # Check if group has members
            if group_entity.member_user_names:
                raise DeleteConflictException(
                    "Cannot delete entity, must remove users from group first."
                )

            del store.GROUPS[group_name]

    def update_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        new_path: pathType | None = None,
        new_group_name: groupNameType | None = None,
        **kwargs,
    ) -> None:
        store = self._get_store(context)
        target_name = new_group_name or group_name

        with self._group_lock:
            group_entity = self._get_group_entity(store, group_name)

            # Check if new name already exists (if changing name)
            if new_group_name and new_group_name != group_name:
                if new_group_name in store.GROUPS:
                    raise EntityAlreadyExistsException(
                        f"Group with name {new_group_name} already exists."
                    )

            # Update path if provided
            if new_path is not None:
                group_entity.group["Path"] = new_path
                # Update ARN with new path
                group_entity.group["Arn"] = self._build_group_arn(context, new_path, target_name)

            # Update name if provided
            if new_group_name and new_group_name != group_name:
                group_entity.group["GroupName"] = new_group_name
                # Update ARN with new name
                path = group_entity.group.get("Path", "/")
                group_entity.group["Arn"] = self._build_group_arn(context, path, new_group_name)
                # Move in store
                store.GROUPS[new_group_name] = store.GROUPS.pop(group_name)

    # ------------------------------ Group Membership Operations ------------------------------ #

    def add_user_to_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        user_name: existingUserNameType,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        self._get_user_or_raise_error(user_name=user_name, context=context)

        with self._group_lock:
            group_entity = self._get_group_entity(store, group_name)

            # Add user if not already a member (idempotent)
            if user_name not in group_entity.member_user_names:
                group_entity.member_user_names.append(user_name)

    def remove_user_from_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        user_name: existingUserNameType,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        self._get_user_or_raise_error(user_name=user_name, context=context)

        with self._group_lock:
            group_entity = self._get_group_entity(store, group_name)

            if user_name in group_entity.member_user_names:
                group_entity.member_user_names.remove(user_name)

    def list_groups_for_user(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListGroupsForUserResponse:
        store = self._get_store(context)
        self._get_user_or_raise_error(user_name=user_name, context=context)

        with self._group_lock:
            groups = []
            for group_entity in store.GROUPS.values():
                if user_name in group_entity.member_user_names:
                    groups.append(Group(group_entity.group))

        # Sort by group name
        sorted_groups = sorted(groups, key=lambda g: g.get("GroupName", "").lower())

        return ListGroupsForUserResponse(Groups=sorted_groups, IsTruncated=False)

    # ------------------------------ Group Inline Policy Operations ------------------------------ #

    def put_group_policy(
        self,
        context: RequestContext,
        group_name: groupNameType,
        policy_name: policyNameType,
        policy_document: policyDocumentType,
        **kwargs,
    ) -> None:
        # Validate policy document
        validator = IAMPolicyDocumentValidator(policy_document)
        validator.validate()

        store = self._get_store(context)
        with self._group_lock:
            group_entity = self._get_group_entity(store, group_name)
            group_entity.inline_policies[policy_name] = quote(policy_document)

    def get_group_policy(
        self,
        context: RequestContext,
        group_name: groupNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> GetGroupPolicyResponse:
        store = self._get_store(context)
        with self._group_lock:
            group_entity = self._get_group_entity(store, group_name)

            policy_document = group_entity.inline_policies.get(policy_name)
            if policy_document is None:
                raise NoSuchEntityException(
                    f"The group policy with name {policy_name} cannot be found."
                )

        return GetGroupPolicyResponse(
            GroupName=group_name,
            PolicyName=policy_name,
            PolicyDocument=policy_document,
        )

    def list_group_policies(
        self,
        context: RequestContext,
        group_name: groupNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListGroupPoliciesResponse:
        store = self._get_store(context)
        with self._group_lock:
            group_entity = self._get_group_entity(store, group_name)
            policy_names = sorted(group_entity.inline_policies.keys())

        return ListGroupPoliciesResponse(PolicyNames=policy_names, IsTruncated=False)

    def delete_group_policy(
        self,
        context: RequestContext,
        group_name: groupNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> None:
        store = self._get_store(context)
        with self._group_lock:
            group_entity = self._get_group_entity(store, group_name)

            if policy_name not in group_entity.inline_policies:
                raise NoSuchEntityException(
                    f"The group policy with name {policy_name} cannot be found."
                )

            del group_entity.inline_policies[policy_name]

    # ------------------------------ Group Managed Policy Operations ------------------------------ #

    def attach_group_policy(
        self,
        context: RequestContext,
        group_name: groupNameType,
        policy_arn: arnType,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        with self._group_lock, self._policy_lock:
            group_entity = self._get_group_entity(store, group_name)
            self._assert_policy_exists(store, policy_arn)

            # Add policy if not already attached (idempotent)
            if policy_arn not in group_entity.attached_policy_arns:
                group_entity.attached_policy_arns.append(policy_arn)
                self._attach_policy(store, policy_arn)

    def detach_group_policy(
        self,
        context: RequestContext,
        group_name: groupNameType,
        policy_arn: arnType,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        with self._group_lock, self._policy_lock:
            group_entity = self._get_group_entity(store, group_name)

            # Check if policy is attached
            if policy_arn not in group_entity.attached_policy_arns:
                raise NoSuchEntityException(f"Policy {policy_arn} was not found.")

            # Remove the policy
            group_entity.attached_policy_arns.remove(policy_arn)
            self._detach_policy(store, policy_arn)

    def list_attached_group_policies(
        self,
        context: RequestContext,
        group_name: groupNameType,
        path_prefix: pathPrefixType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListAttachedGroupPoliciesResponse:
        store = self._get_store(context)

        with self._group_lock:
            group_entity = self._get_group_entity(store, group_name)

            # Build list of attached policies
            attached_policies: list[AttachedPolicy] = []
            for policy_arn in group_entity.attached_policy_arns:
                # Extract policy name from ARN
                policy_name = policy_arn.split("/")[-1]
                attached_policies.append(
                    AttachedPolicy(PolicyName=policy_name, PolicyArn=policy_arn)
                )

        # Sort by policy name
        attached_policies.sort(key=lambda p: p.get("PolicyName", "").lower())

        return ListAttachedGroupPoliciesResponse(
            AttachedPolicies=attached_policies, IsTruncated=False
        )

    def create_service_linked_role(
        self,
        context: RequestContext,
        aws_service_name: groupNameType,
        description: roleDescriptionType = None,
        custom_suffix: customSuffixType = None,
        **kwargs,
    ) -> CreateServiceLinkedRoleResponse:
        store = self._get_store(context)
        policy_doc = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": aws_service_name},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        service_role_data = SERVICE_LINKED_ROLES.get(aws_service_name)

        path = f"{SERVICE_LINKED_ROLE_PATH_PREFIX}/{aws_service_name}/"
        if service_role_data:
            if custom_suffix and not service_role_data["suffix_allowed"]:
                raise InvalidInputException(f"Custom suffix is not allowed for {aws_service_name}")
            role_name = service_role_data.get("role_name")
            attached_policies = service_role_data["attached_policies"]
        else:
            role_name = f"AWSServiceRoleFor{aws_service_name.split('.')[0].capitalize()}"
            attached_policies = []
        if custom_suffix:
            role_name = f"{role_name}_{custom_suffix}"

        with self._role_lock:
            # Check for role duplicates
            if role_name in store.ROLES:
                raise InvalidInputException(
                    f"Service role name {role_name} has been taken in this account, please try a different suffix."
                )

            # Generate role ID and ARN
            role_id = self._generate_role_id(context)
            role_arn = self._build_role_arn(context, path, role_name)

            # Build the Role object
            role = Role(
                Path=path,
                RoleName=role_name,
                RoleId=role_id,
                Arn=role_arn,
                CreateDate=datetime.now(tz=UTC),
                AssumeRolePolicyDocument=quote(policy_doc),
                MaxSessionDuration=3600,
                RoleLastUsed=RoleLastUsed(),
            )

            if description:
                role["Description"] = description

            # Create role entity with linked_service set
            role_entity = RoleEntity(role=role, linked_service=aws_service_name)

            # Attach policies
            for policy_arn in attached_policies:
                role_entity.attached_policy_arns.append(policy_arn)

            store.ROLES[role_name] = role_entity

        return CreateServiceLinkedRoleResponse(Role=role)

    def delete_service_linked_role(
        self, context: RequestContext, role_name: roleNameType, **kwargs
    ) -> DeleteServiceLinkedRoleResponse:
        store = self._get_store(context)

        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)
            role_path = role_entity.role.get("Path", "/")

            # Clear attached policies (service-linked roles don't enforce detach before delete)
            role_entity.attached_policy_arns.clear()

            # Delete the role from native store
            del store.ROLES[role_name]

        return DeleteServiceLinkedRoleResponse(
            DeletionTaskId=f"task{role_path}{role_name}/{uuid.uuid4()}"
        )

    def get_service_linked_role_deletion_status(
        self, context: RequestContext, deletion_task_id: DeletionTaskIdType, **kwargs
    ) -> GetServiceLinkedRoleDeletionStatusResponse:
        # TODO: check if task id is valid
        return GetServiceLinkedRoleDeletionStatusResponse(Status=DeletionTaskStatusType.SUCCEEDED)

    # ------------------------------ User Permissions Boundary Operations ------------------------------ #

    def put_user_permissions_boundary(
        self,
        context: RequestContext,
        user_name: userNameType,
        permissions_boundary: arnType,
        **kwargs,
    ) -> None:
        # Validate the permissions boundary
        self._validate_permissions_boundary(context, permissions_boundary)

        store = self._get_store(context)
        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)
            user_entity.user["PermissionsBoundary"] = AttachedPermissionsBoundary(
                PermissionsBoundaryType="Policy",
                PermissionsBoundaryArn=permissions_boundary,
            )

    def delete_user_permissions_boundary(
        self, context: RequestContext, user_name: userNameType, **kwargs
    ) -> None:
        store = self._get_store(context)
        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)
            user_entity.user.pop("PermissionsBoundary", None)

    # ------------------------------ User CRUD Operations ------------------------------ #

    def create_user(
        self,
        context: RequestContext,
        user_name: userNameType,
        path: pathType = None,
        permissions_boundary: arnType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> CreateUserResponse:
        store = self._get_store(context)

        # Validate tags
        self._validate_tags(tags, case_sensitive=False)

        # Validate permissions boundary if provided
        if permissions_boundary:
            self._validate_permissions_boundary(context, permissions_boundary)

        with self._user_lock:
            # Check if user already exists
            if user_name in store.USERS:
                raise EntityAlreadyExistsException(f"User with name {user_name} already exists.")

            # Generate user ID and ARN
            user_id = self._generate_user_id(context, tags)
            path = path or "/"
            user_arn = self._build_user_arn(context, path, user_name)

            # Build the User object
            user = User(
                Path=path,
                UserName=user_name,
                UserId=user_id,
                Arn=user_arn,
                CreateDate=datetime.now(tz=UTC),
            )

            if tags:
                user["Tags"] = tags
            if permissions_boundary:
                user["PermissionsBoundary"] = AttachedPermissionsBoundary(
                    PermissionsBoundaryType="Policy",
                    PermissionsBoundaryArn=permissions_boundary,
                )

            # Create user entity and store
            user_entity = UserEntity(user=user)
            store.USERS[user_name] = user_entity

        return CreateUserResponse(User=User(user))

    def get_user(
        self, context: RequestContext, user_name: existingUserNameType = None, **kwargs
    ) -> GetUserResponse:
        store = self._get_store(context)

        # Handle case where no username is provided (get current user)
        with self._user_lock:
            if not user_name:
                try:
                    user_name = self._get_user_name_from_access_key_context(context)
                except ValidationError:
                    # Check if it's the root principal
                    access_key_id = extract_access_key_id_from_auth_header(context.request.headers)
                    sts_client = connect_to(
                        region_name=context.region,
                        aws_access_key_id=access_key_id,
                        aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
                    ).sts
                    caller_identity = sts_client.get_caller_identity()
                    caller_arn = caller_identity["Arn"]

                    # Check if this is the root user
                    if caller_arn.endswith(":root"):
                        return GetUserResponse(
                            User=User(
                                UserId=context.account_id,
                                Arn=caller_arn,
                                CreateDate=datetime.now(),
                                PasswordLastUsed=datetime.now(),
                            )
                        )
                    raise

            user_entity = self._get_user_entity(store, user_name)
            # Return a copy of the user
            user = User(user_entity.user)

        return GetUserResponse(User=user)

    def list_users(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListUsersResponse:
        store = self._get_store(context)

        def _filter(user: User) -> bool:
            if path_prefix:
                return user.get("Path", "/").startswith(path_prefix)
            return True

        def _map_to_response(user_entity: UserEntity) -> User:
            user = user_entity.user
            # ListUsers response includes all user fields
            list_user = User(
                Path=user["Path"],
                UserName=user["UserName"],
                UserId=user["UserId"],
                Arn=user["Arn"],
                CreateDate=user["CreateDate"],
            )
            if permissions_boundary := user.get("PermissionsBoundary"):
                list_user["PermissionsBoundary"] = permissions_boundary
            if tags := user.get("Tags"):
                list_user["Tags"] = tags
            return list_user

        # Sort users by UserName (case-insensitive, as AWS does)
        with self._user_lock:
            users = list(store.USERS.values())
            sorted_users = sorted(users, key=lambda e: e.user.get("UserName", "").lower())

            paginated_list = PaginatedList([_map_to_response(e) for e in sorted_users])

        def _token_generator(user: User) -> str:
            return user.get("UserName")

        # Decode marker if provided (markers are base64-encoded)
        if marker:
            marker = base64.b64decode(marker).decode("utf-8")

        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator,
            next_token=marker,
            page_size=max_items or 100,
            filter_function=_filter,
        )

        if next_marker:
            # Encode the marker as base64 to make it opaque
            next_marker = base64.b64encode(next_marker.encode("utf-8")).decode("utf-8")
            return ListUsersResponse(Users=result, IsTruncated=True, Marker=next_marker)
        else:
            return ListUsersResponse(Users=result, IsTruncated=False)

    def update_user(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        new_path: pathType = None,
        new_user_name: userNameType = None,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            # Check if new username already exists (if renaming)
            if new_user_name and new_user_name != user_name and new_user_name in store.USERS:
                raise EntityAlreadyExistsException(
                    f"User with name {new_user_name} already exists."
                )

            # Update path if provided
            if new_path is not None:
                user_entity.user["Path"] = new_path
                # Update ARN with new path
                user_entity.user["Arn"] = self._build_user_arn(
                    context, new_path, new_user_name or user_name
                )

            # Update username if provided
            if new_user_name and new_user_name != user_name:
                # Update ARN with new username
                path = user_entity.user.get("Path", "/")
                user_entity.user["Arn"] = self._build_user_arn(context, path, new_user_name)
                user_entity.user["UserName"] = new_user_name
                # Move to new key in store
                del store.USERS[user_name]
                store.USERS[new_user_name] = user_entity

    def delete_user(
        self, context: RequestContext, user_name: existingUserNameType, **kwargs
    ) -> None:
        store = self._get_store(context)

        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            # Check if user has attached managed policies
            if user_entity.attached_policy_arns:
                raise DeleteConflictException(
                    "Cannot delete entity, must detach all policies first."
                )

            # Check if user has inline policies
            if user_entity.inline_policies:
                raise DeleteConflictException("Cannot delete entity, must delete policies first.")

            # TODO test if SSH keys block user deletion
            # Check if user has access keys
            if user_entity.access_keys:
                raise DeleteConflictException(
                    "Cannot delete entity, must delete access keys first."
                )

            if user_entity.service_specific_credentials:
                raise DeleteConflictException(
                    "Cannot delete entity, must remove referenced objects first."
                )

            # Delete the user from native store
            del store.USERS[user_name]

    # ------------------------------ User Login Profile Operations ------------------------------ #

    def create_login_profile(
        self,
        context: RequestContext,
        user_name: userNameType | None = None,
        password: passwordType | None = None,
        password_reset_required: booleanType | None = None,
        **kwargs,
    ) -> CreateLoginProfileResponse:
        store = self._get_store(context)

        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            # Check if login profile already exists
            if user_entity.login_profile is not None:
                raise EntityAlreadyExistsException(
                    f"Login Profile for user {user_name} already exists."
                )

            # Create the login profile
            login_profile = LoginProfile(
                UserName=user_name,
                CreateDate=datetime.now(tz=UTC),
                PasswordResetRequired=password_reset_required or False,
            )

            # Store login profile and password
            user_entity.login_profile = login_profile
            user_entity.password = password

        return CreateLoginProfileResponse(LoginProfile=login_profile)

    def get_login_profile(
        self, context: RequestContext, user_name: userNameType | None = None, **kwargs
    ) -> GetLoginProfileResponse:
        store = self._get_store(context)

        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            # Check if login profile exists
            if user_entity.login_profile is None:
                raise NoSuchEntityException(f"Login Profile for User {user_name} cannot be found.")

            # Return a copy of the login profile
            login_profile = LoginProfile(user_entity.login_profile)

        return GetLoginProfileResponse(LoginProfile=login_profile)

    def update_login_profile(
        self,
        context: RequestContext,
        user_name: userNameType,
        password: passwordType = None,
        password_reset_required: booleanObjectType = None,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            # Check if login profile exists
            if user_entity.login_profile is None:
                raise NoSuchEntityException(f"Login Profile for User {user_name} cannot be found.")

            # Update password if provided
            if password is not None:
                user_entity.password = password

            # Update PasswordResetRequired if provided
            if password_reset_required is not None:
                user_entity.login_profile["PasswordResetRequired"] = password_reset_required

    def delete_login_profile(
        self, context: RequestContext, user_name: userNameType | None = None, **kwargs
    ) -> None:
        store = self._get_store(context)

        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            # Check if login profile exists
            if user_entity.login_profile is None:
                raise NoSuchEntityException(f"Login Profile for User {user_name} cannot be found.")

            # Delete the login profile
            user_entity.login_profile = None
            user_entity.password = None

    # ------------------------------ User Inline Policy Operations ------------------------------ #

    def put_user_policy(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        policy_name: policyNameType,
        policy_document: policyDocumentType,
        **kwargs,
    ) -> None:
        # Validate policy document
        validator = IAMPolicyDocumentValidator(policy_document)
        validator.validate()

        store = self._get_store(context)
        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)
            # Always quote policies for consistency
            user_entity.inline_policies[policy_name] = quote(policy_document)

    def get_user_policy(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> GetUserPolicyResponse:
        store = self._get_store(context)
        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            policy_document = user_entity.inline_policies.get(policy_name)
            if policy_document is None:
                raise NoSuchEntityException(
                    f"The user policy with name {policy_name} cannot be found."
                )

        return GetUserPolicyResponse(
            UserName=user_name,
            PolicyName=policy_name,
            PolicyDocument=policy_document,
        )

    def list_user_policies(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListUserPoliciesResponse:
        store = self._get_store(context)
        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)
            policy_names = sorted(user_entity.inline_policies.keys())

        paginated_list = PaginatedList(policy_names)

        def _token_generator(name: str) -> str:
            return name

        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator,
            next_token=marker,
            page_size=max_items or 100,
        )

        if next_marker:
            return ListUserPoliciesResponse(
                PolicyNames=result, IsTruncated=True, Marker=next_marker
            )
        else:
            return ListUserPoliciesResponse(PolicyNames=result, IsTruncated=False)

    def delete_user_policy(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> None:
        store = self._get_store(context)
        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            if policy_name not in user_entity.inline_policies:
                raise NoSuchEntityException(
                    f"The user policy with name {policy_name} cannot be found."
                )

            del user_entity.inline_policies[policy_name]

    def attach_role_policy(
        self, context: RequestContext, role_name: roleNameType, policy_arn: arnType, **kwargs
    ) -> None:
        # Validate ARN format
        if not POLICY_ARN_REGEX.match(policy_arn):
            raise ValidationError(f"ARN {policy_arn} is not valid.")

        store = self._get_store(context)

        with self._role_lock, self._policy_lock:
            role_entity = self._get_role_entity(store, role_name)
            self._assert_policy_exists(store, policy_arn)

            # Add policy if not already attached (idempotent)
            if policy_arn not in role_entity.attached_policy_arns:
                role_entity.attached_policy_arns.append(policy_arn)
                self._attach_policy(store, policy_arn)

    def detach_role_policy(
        self, context: RequestContext, role_name: roleNameType, policy_arn: arnType, **kwargs
    ) -> None:
        store = self._get_store(context)
        with self._role_lock, self._policy_lock:
            role_entity = self._get_role_entity(store, role_name)

            # Check if policy is attached
            if policy_arn not in role_entity.attached_policy_arns:
                raise NoSuchEntityException(f"Policy {policy_arn} was not found.")

            # Remove the policy
            role_entity.attached_policy_arns.remove(policy_arn)
            self._detach_policy(store, policy_arn)

    def list_attached_role_policies(
        self,
        context: RequestContext,
        role_name: roleNameType,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListAttachedRolePoliciesResponse:
        store = self._get_store(context)

        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)

            # Build list of attached policies
            attached_policies: list[AttachedPolicy] = []
            for policy_arn in role_entity.attached_policy_arns:
                # Extract policy name from ARN
                policy_name = policy_arn.split("/")[-1]
                policy_path = "/" + "/".join(policy_arn.split("/")[:-1]).split(":policy/")[-1]
                if policy_path == "/":
                    policy_path = "/"

                # Filter by path_prefix if provided
                if path_prefix and not policy_path.startswith(path_prefix):
                    continue

                attached_policies.append(
                    AttachedPolicy(PolicyName=policy_name, PolicyArn=policy_arn)
                )

        # Sort by policy name (case-insensitive, as AWS does)
        attached_policies.sort(key=lambda p: p.get("PolicyName", "").lower(), reverse=True)

        paginated_list = PaginatedList(attached_policies)

        def _token_generator(policy: AttachedPolicy) -> str:
            return policy.get("PolicyName", "")

        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator,
            next_token=marker,
            page_size=max_items or 100,
        )

        if next_marker:
            return ListAttachedRolePoliciesResponse(
                AttachedPolicies=result, IsTruncated=True, Marker=next_marker
            )
        else:
            return ListAttachedRolePoliciesResponse(AttachedPolicies=result, IsTruncated=False)

    # ------------------------------ Role Permissions Boundary Operations ------------------------------ #

    def put_role_permissions_boundary(
        self,
        context: RequestContext,
        role_name: roleNameType,
        permissions_boundary: arnType,
        **kwargs,
    ) -> None:
        # Validate the permissions boundary
        self._validate_permissions_boundary(context, permissions_boundary)

        store = self._get_store(context)
        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)
            role_entity.role["PermissionsBoundary"] = {
                "PermissionsBoundaryType": "Policy",
                "PermissionsBoundaryArn": permissions_boundary,
            }

    def delete_role_permissions_boundary(
        self, context: RequestContext, role_name: roleNameType, **kwargs
    ) -> None:
        store = self._get_store(context)
        with self._role_lock:
            role_entity = self._get_role_entity(store, role_name)
            role_entity.role.pop("PermissionsBoundary", None)

    # ------------------------------ User Managed Policy Operations ------------------------------ #

    def attach_user_policy(
        self, context: RequestContext, user_name: userNameType, policy_arn: arnType, **kwargs
    ) -> None:
        # Validate ARN format
        if not POLICY_ARN_REGEX.match(policy_arn):
            raise ValidationError(f"ARN {policy_arn} is not valid.")

        store = self._get_store(context)

        with self._user_lock, self._policy_lock:
            user_entity = self._get_user_entity(store, user_name)
            self._assert_policy_exists(store, policy_arn)

            # Add policy if not already attached (idempotent)
            if policy_arn not in user_entity.attached_policy_arns:
                user_entity.attached_policy_arns.append(policy_arn)
                self._attach_policy(store, policy_arn)

    def detach_user_policy(
        self, context: RequestContext, user_name: userNameType, policy_arn: arnType, **kwargs
    ) -> None:
        store = self._get_store(context)

        with self._user_lock, self._policy_lock:
            user_entity = self._get_user_entity(store, user_name)

            # Check if policy is attached
            if policy_arn not in user_entity.attached_policy_arns:
                raise NoSuchEntityException(f"Policy {policy_arn} was not found.")

            # Remove the policy
            user_entity.attached_policy_arns.remove(policy_arn)
            self._detach_policy(store, policy_arn)

    def list_attached_user_policies(
        self,
        context: RequestContext,
        user_name: userNameType,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListAttachedUserPoliciesResponse:
        store = self._get_store(context)

        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            # Build list of attached policies
            attached_policies: list[AttachedPolicy] = []
            for policy_arn in user_entity.attached_policy_arns:
                # Extract policy name from ARN
                policy_name = policy_arn.split("/")[-1]
                policy_path = "/" + "/".join(policy_arn.split("/")[:-1]).split(":policy/")[-1]
                if policy_path == "/":
                    policy_path = "/"

                # Filter by path_prefix if provided
                if path_prefix and not policy_path.startswith(path_prefix):
                    continue

                attached_policies.append(
                    AttachedPolicy(PolicyName=policy_name, PolicyArn=policy_arn)
                )

        # Sort by policy name (case-insensitive, as AWS does)
        attached_policies.sort(key=lambda p: p.get("PolicyName", "").lower())

        paginated_list = PaginatedList(attached_policies)

        def _token_generator(policy: AttachedPolicy) -> str:
            return policy.get("PolicyName", "")

        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator,
            next_token=marker,
            page_size=max_items or 100,
        )

        if next_marker:
            return ListAttachedUserPoliciesResponse(
                AttachedPolicies=result, IsTruncated=True, Marker=next_marker
            )
        else:
            return ListAttachedUserPoliciesResponse(AttachedPolicies=result, IsTruncated=False)

    # ------------------------------ User Tag Operations ------------------------------ #

    def tag_user(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        self._validate_tags(tags, case_sensitive=False)

        store = self._get_store(context)
        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            # Initialize tags if not present
            if "Tags" not in user_entity.user or user_entity.user["Tags"] is None:
                user_entity.user["Tags"] = []

            # Merge tags - update existing keys, add new ones, case-insensitive
            existing_keys = {
                tag["Key"].lower(): i for i, tag in enumerate(user_entity.user["Tags"])
            }
            for tag in tags:
                key = tag["Key"].lower()
                if key in existing_keys:
                    user_entity.user["Tags"][existing_keys[key]] = tag
                else:
                    user_entity.user["Tags"].append(tag)

    def untag_user(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        self._validate_tag_keys(tag_keys)

        store = self._get_store(context)
        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            if "Tags" in user_entity.user and user_entity.user["Tags"]:
                # Remove tags with matching keys (case-insensitive)
                tag_keys_set = {key.lower() for key in tag_keys}
                user_entity.user["Tags"] = [
                    tag
                    for tag in user_entity.user["Tags"]
                    if tag["Key"].lower() not in tag_keys_set
                ]

    def list_user_tags(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListUserTagsResponse:
        store = self._get_store(context)
        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)
            tags = list(user_entity.user.get("Tags") or [])

        paginated_list = PaginatedList(tags)

        def _token_generator(tag: Tag) -> str:
            return tag.get("Key")

        # base64 encode/decode to avoid plaintext tag as marker
        if marker:
            marker = base64.b64decode(marker).decode("utf-8")

        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator, next_token=marker, page_size=max_items or 100
        )

        if next_marker:
            next_marker = base64.b64encode(next_marker.encode("utf-8")).decode("utf-8")
            return ListUserTagsResponse(Tags=result, IsTruncated=True, Marker=next_marker)
        else:
            return ListUserTagsResponse(Tags=result, IsTruncated=False)

    # ------------------------------ User Access Key Operations ------------------------------ #

    def _generate_access_key_id(self, context: RequestContext) -> str:
        """Generate an access key ID with the appropriate prefix based on config."""
        prefix = "AKIA" if config.PARITY_AWS_ACCESS_KEY_ID else "LKIA"
        return generate_iam_identifier(context.account_id, prefix=prefix, total_length=20)

    def _generate_secret_access_key(self) -> str:
        """Generate a 40-character random secret access key."""
        charset = string.ascii_letters + string.digits + "+/"
        return "".join(random.choices(charset, k=40))

    def _get_access_key_entity(
        self, user_entity: UserEntity, access_key_id: str
    ) -> AccessKeyEntity:
        """Find an access key entity in a user's dict, raise NoSuchEntityException if not found."""
        key_entity = user_entity.access_keys.get(access_key_id)
        if not key_entity:
            raise NoSuchEntityException(f"The Access Key with id {access_key_id} cannot be found.")
        return key_entity

    def _get_caller_arn_from_access_key_context(self, context: RequestContext) -> str:
        """
        Get the caller ARN from the request context via STS GetCallerIdentity.
        """
        access_key_id = extract_access_key_id_from_auth_header(context.request.headers)
        sts_client = connect_to(
            region_name=context.region,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
        ).sts
        caller_identity = sts_client.get_caller_identity()
        return caller_identity["Arn"]

    def _get_user_name_from_access_key_context(self, context: RequestContext) -> str:
        """
        Derive the user name from the request context for access key operations.
        First tries to look up the access key in the store, then falls back to STS.
        """
        store = self._get_store(context)
        access_key_id = extract_access_key_id_from_auth_header(context.request.headers)

        # Try to find user directly from our access key index
        user_name = store.ACCESS_KEY_INDEX.get(access_key_id)
        if user_name:
            return user_name

        raise ValidationError(
            "Must specify userName when calling with non-User credentials",
        )

    def create_access_key(
        self,
        context: RequestContext,
        user_name: existingUserNameType = None,
        **kwargs,
    ) -> CreateAccessKeyResponse:
        store = self._get_store(context)

        # Derive user_name from context if not provided
        with self._user_lock:
            if not user_name:
                user_name = self._get_user_name_from_access_key_context(context)

            user_entity = self._get_user_entity(store, user_name)

            # Check 2-key limit
            if len(user_entity.access_keys) >= LIMIT_ACCESS_KEYS_PER_USER:
                raise LimitExceededException(
                    f"Cannot exceed quota for AccessKeysPerUser: {LIMIT_ACCESS_KEYS_PER_USER}"
                )

            # Generate access key
            access_key_id = self._generate_access_key_id(context)
            secret_access_key = self._generate_secret_access_key()

            access_key = AccessKey(
                UserName=user_name,
                AccessKeyId=access_key_id,
                Status="Active",
                SecretAccessKey=secret_access_key,
                CreateDate=datetime.now(tz=UTC),
            )

            # Create entity and add to user's dict
            key_entity = AccessKeyEntity(access_key=access_key)
            user_entity.access_keys[access_key_id] = key_entity

            # Add to index for efficient lookups
            store.ACCESS_KEY_INDEX[access_key_id] = user_name

        return CreateAccessKeyResponse(AccessKey=access_key)

    def delete_access_key(
        self,
        context: RequestContext,
        access_key_id: accessKeyIdType,
        user_name: existingUserNameType = None,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        with self._user_lock:
            # Derive user_name from context if not provided
            if not user_name:
                user_name = self._get_user_name_from_access_key_context(context)
            user_entity = self._get_user_entity(store, user_name)
            # Validate key exists
            self._get_access_key_entity(user_entity, access_key_id)

            # Remove from user's dict
            del user_entity.access_keys[access_key_id]

            # Remove from index
            store.ACCESS_KEY_INDEX.pop(access_key_id, None)

    def list_access_keys(
        self,
        context: RequestContext,
        user_name: existingUserNameType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListAccessKeysResponse:
        store = self._get_store(context)

        with self._user_lock:
            # Derive user_name from context if not provided
            if not user_name:
                user_name = self._get_user_name_from_access_key_context(context)
            user_entity = self._get_user_entity(store, user_name)

            # Convert to AccessKeyMetadata (no SecretAccessKey)
            metadata_list = [
                AccessKeyMetadata(
                    UserName=key_entity.access_key["UserName"],
                    AccessKeyId=key_entity.access_key["AccessKeyId"],
                    Status=key_entity.access_key["Status"],
                    CreateDate=key_entity.access_key.get("CreateDate"),
                )
                for key_entity in user_entity.access_keys.values()
            ]

        # Apply pagination
        paginated_list = PaginatedList(metadata_list)

        def _token_generator(meta: AccessKeyMetadata) -> str:
            return meta["AccessKeyId"]

        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator,
            next_token=marker,
            page_size=max_items or 100,
        )

        if next_marker:
            return ListAccessKeysResponse(
                AccessKeyMetadata=result, IsTruncated=True, Marker=next_marker
            )
        else:
            return ListAccessKeysResponse(AccessKeyMetadata=result, IsTruncated=False)

    def update_access_key(
        self,
        context: RequestContext,
        access_key_id: accessKeyIdType,
        status: statusType,
        user_name: existingUserNameType = None,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        with self._user_lock:
            # Derive user_name from context if not provided
            if not user_name:
                user_name = self._get_user_name_from_access_key_context(context)
            user_entity = self._get_user_entity(store, user_name)
            key_entity = self._get_access_key_entity(user_entity, access_key_id)

            # Update status
            key_entity.access_key["Status"] = status

    def get_access_key_last_used(
        self,
        context: RequestContext,
        access_key_id: accessKeyIdType,
        **kwargs,
    ) -> GetAccessKeyLastUsedResponse:
        store = self._get_store(context)

        with self._user_lock:
            # Look up user_name from index
            user_name = store.ACCESS_KEY_INDEX.get(access_key_id)
            if not user_name:
                # AWS returns AccessDenied (not NoSuchEntity) for unknown keys
                # to prevent enumeration attacks
                raise AccessDeniedError(
                    f"User: {self._get_caller_arn_from_access_key_context(context)} is not authorized to perform "
                    f"iam:GetAccessKeyLastUsed on resource: access key {access_key_id}"
                )

            user_entity = self._get_user_entity(store, user_name)
            key_entity = self._get_access_key_entity(user_entity, access_key_id)

            # Return last_used info or N/A values for unused keys (AWS behavior)
            if key_entity.last_used:
                access_key_last_used = key_entity.last_used
            else:
                access_key_last_used = AccessKeyLastUsed(
                    ServiceName="N/A",
                    Region="N/A",
                )

        return GetAccessKeyLastUsedResponse(
            UserName=user_name,
            AccessKeyLastUsed=access_key_last_used,
        )

    # ------------------------------ Service specific credentials ------------------------------ #

    def _get_user_or_raise_error(self, user_name: str, context: RequestContext) -> UserEntity:
        """
        Return the user from the store, or raise the proper exception if no user can be found.

        :param user_name: Username to find
        :param context: Request context
        :return: A user object
        """
        store = self._get_store(context)
        user = store.USERS.get(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")
        return user

    def _validate_service_name(self, service_name: str) -> None:
        """
        Validate if the service provided is supported.

        :param service_name: Service name to check
        """
        if service_name not in ["codecommit.amazonaws.com", "cassandra.amazonaws.com"]:
            raise NoSuchEntityException(
                f"No such service {service_name} is supported for Service Specific Credentials"
            )

    def _validate_credential_id(self, credential_id: str) -> None:
        """
        Validate if the credential id is correctly formed.

        :param credential_id: Credential ID to check
        """
        if not CREDENTIAL_ID_REGEX.match(credential_id):
            raise ValidationListError(
                [
                    "Value at 'serviceSpecificCredentialId' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w]+"
                ]
            )

    def _generate_service_password(self):
        """
        Generate a new service password for a service specific credential.

        :return: 60 letter password ending in `=`
        """
        password_charset = string.ascii_letters + string.digits + "+/"
        # password always ends in = for some reason - but it is not base64
        return "".join(random.choices(password_charset, k=59)) + "="

    def _generate_credential_id(self, context: RequestContext):
        """
        Generate a credential ID.
        Credentials have a similar structure as access key ids, and also contain the account id encoded in them.
        Example: `ACCAQAAAAAAAPBAFQJI5W` for account `000000000000`

        :param context: Request context (to extract account id)
        :return: New credential id.
        """
        return generate_iam_identifier(context.account_id, prefix="ACCA", total_length=21)

    def _new_service_specific_credential(
        self, user_name: str, service_name: str, context: RequestContext
    ) -> ServiceSpecificCredential:
        """
        Create a new service specific credential for the given username and service.

        :param user_name: Username the credential will be assigned to.
        :param service_name: Service the credential will be used for.
        :param context: Request context, used to extract the account id.
        :return: New ServiceSpecificCredential
        """
        password = self._generate_service_password()
        credential_id = self._generate_credential_id(context)
        return ServiceSpecificCredential(
            CreateDate=datetime.now(),
            ServiceName=service_name,
            ServiceUserName=f"{user_name}-at-{context.account_id}",
            ServicePassword=password,
            ServiceSpecificCredentialId=credential_id,
            UserName=user_name,
            Status=statusType.Active,
        )

    def _find_credential_in_user_by_id(
        self, user_name: str, credential_id: str, context: RequestContext
    ) -> ServiceSpecificCredential:
        """
        Find a credential by a given username and id.
        Raises errors if the user or credential is not found.

        :param user_name: Username of the user the credential is assigned to.
        :param credential_id: Credential ID to check
        :param context: Request context (used to determine account and region)
        :return: Service specific credential
        """
        user = self._get_user_or_raise_error(user_name, context)
        self._validate_credential_id(credential_id)
        matching_credentials = [
            cred
            for cred in user.service_specific_credentials
            if cred["ServiceSpecificCredentialId"] == credential_id
        ]
        if not matching_credentials:
            raise NoSuchEntityException(f"No such credential {credential_id} exists")
        return matching_credentials[0]

    def _validate_status(self, status: str):
        """
        Validate if the status has an accepted value.
        Raises a ValidationError if the status is invalid.

        :param status: Status to check
        """
        try:
            statusType(status)
        except ValueError:
            raise ValidationListError(
                [
                    "Value at 'status' failed to satisfy constraint: Member must satisfy enum value set"
                ]
            )

    def build_dict_with_only_defined_keys(
        self, data: dict[str, Any], typed_dict_type: type[T]
    ) -> T:
        """
        Builds a dict with only the defined keys from a given typed dict.
        Filtering is only present on the first level.

        :param data: Dict to filter.
        :param typed_dict_type: TypedDict subtype containing the attributes allowed to be present in the return value
        :return: shallow copy of the data only containing the keys defined on typed_dict_type
        """
        key_set = inspect.get_annotations(typed_dict_type).keys()
        return {k: v for k, v in data.items() if k in key_set}

    def create_service_specific_credential(
        self,
        context: RequestContext,
        user_name: userNameType,
        service_name: serviceName,
        credential_age_days: credentialAgeDays | None = None,
        **kwargs,
    ) -> CreateServiceSpecificCredentialResponse:
        # TODO add support for credential_age_days
        user = self._get_user_or_raise_error(user_name, context)
        self._validate_service_name(service_name)
        credential = self._new_service_specific_credential(user_name, service_name, context)
        user.service_specific_credentials.append(credential)
        return CreateServiceSpecificCredentialResponse(ServiceSpecificCredential=credential)

    def list_service_specific_credentials(
        self,
        context: RequestContext,
        user_name: userNameType | None = None,
        service_name: serviceName | None = None,
        all_users: allUsers | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListServiceSpecificCredentialsResponse:
        # TODO add support for all_users, marker, max_items
        user = self._get_user_or_raise_error(user_name, context)
        self._validate_service_name(service_name)
        result = [
            self.build_dict_with_only_defined_keys(creds, ServiceSpecificCredentialMetadata)
            for creds in user.service_specific_credentials
            if creds["ServiceName"] == service_name
        ]
        return ListServiceSpecificCredentialsResponse(ServiceSpecificCredentials=result)

    def update_service_specific_credential(
        self,
        context: RequestContext,
        service_specific_credential_id: serviceSpecificCredentialId,
        status: statusType,
        user_name: userNameType = None,
        **kwargs,
    ) -> None:
        self._validate_status(status)

        credential = self._find_credential_in_user_by_id(
            user_name, service_specific_credential_id, context
        )
        credential["Status"] = status

    def reset_service_specific_credential(
        self,
        context: RequestContext,
        service_specific_credential_id: serviceSpecificCredentialId,
        user_name: userNameType = None,
        **kwargs,
    ) -> ResetServiceSpecificCredentialResponse:
        credential = self._find_credential_in_user_by_id(
            user_name, service_specific_credential_id, context
        )
        credential["ServicePassword"] = self._generate_service_password()
        return ResetServiceSpecificCredentialResponse(ServiceSpecificCredential=credential)

    def delete_service_specific_credential(
        self,
        context: RequestContext,
        service_specific_credential_id: serviceSpecificCredentialId,
        user_name: userNameType = None,
        **kwargs,
    ) -> None:
        user = self._get_user_or_raise_error(user_name, context)
        credentials = self._find_credential_in_user_by_id(
            user_name, service_specific_credential_id, context
        )
        try:
            user.service_specific_credentials.remove(credentials)
        # just in case of race conditions
        except ValueError:
            raise NoSuchEntityException(
                f"No such credential {service_specific_credential_id} exists"
            )

    # ------------------------------ Account Password Policy ------------------------------ #

    def update_account_password_policy(
        self,
        context: RequestContext,
        minimum_password_length: minimumPasswordLengthType | None = None,
        require_symbols: booleanType | None = None,
        require_numbers: booleanType | None = None,
        require_uppercase_characters: booleanType | None = None,
        require_lowercase_characters: booleanType | None = None,
        allow_users_to_change_password: booleanType | None = None,
        max_password_age: maxPasswordAgeType | None = None,
        password_reuse_prevention: passwordReusePreventionType | None = None,
        hard_expiry: booleanObjectType | None = None,
        **kwargs,
    ) -> None:
        # Validate constraints
        validation_errors = []
        if minimum_password_length is not None and minimum_password_length > 128:
            validation_errors.append(
                "Value at 'minimumPasswordLength' failed to satisfy constraint: "
                "Member must have value less than or equal to 128"
            )
        if password_reuse_prevention is not None and password_reuse_prevention > 24:
            validation_errors.append(
                "Value at 'passwordReusePrevention' failed to satisfy constraint: "
                "Member must have value less than or equal to 24"
            )
        if max_password_age is not None and max_password_age > 1095:
            validation_errors.append(
                "Value at 'maxPasswordAge' failed to satisfy constraint: "
                "Member must have value less than or equal to 1095"
            )
        if validation_errors:
            raise ValidationListError(validation_errors)

        # Build the password policy with defaults
        expire_passwords = max_password_age is not None and max_password_age > 0

        policy = PasswordPolicy(
            MinimumPasswordLength=minimum_password_length
            if minimum_password_length is not None
            else 6,
            RequireSymbols=require_symbols if require_symbols is not None else False,
            RequireNumbers=require_numbers if require_numbers is not None else False,
            RequireUppercaseCharacters=require_uppercase_characters
            if require_uppercase_characters is not None
            else False,
            RequireLowercaseCharacters=require_lowercase_characters
            if require_lowercase_characters is not None
            else False,
            AllowUsersToChangePassword=allow_users_to_change_password
            if allow_users_to_change_password is not None
            else False,
            ExpirePasswords=expire_passwords,
        )

        # Only include optional fields if they were provided
        if max_password_age is not None:
            policy["MaxPasswordAge"] = max_password_age
        if password_reuse_prevention is not None:
            policy["PasswordReusePrevention"] = password_reuse_prevention
        if hard_expiry is not None:
            policy["HardExpiry"] = hard_expiry

        store = self._get_store(context)
        store.PASSWORD_POLICY = policy

    def get_account_password_policy(
        self,
        context: RequestContext,
        **kwargs,
    ) -> GetAccountPasswordPolicyResponse:
        store = self._get_store(context)
        if store.PASSWORD_POLICY is None:
            raise NoSuchEntityException(
                f"The Password Policy with domain name {context.account_id} cannot be found."
            )
        return GetAccountPasswordPolicyResponse(PasswordPolicy=store.PASSWORD_POLICY)

    def delete_account_password_policy(
        self,
        context: RequestContext,
        **kwargs,
    ) -> None:
        store = self._get_store(context)
        if store.PASSWORD_POLICY is None:
            raise NoSuchEntityException(
                "The account policy with name PasswordPolicy cannot be found."
            )
        store.PASSWORD_POLICY = None

    # ------------------------------ SAML Providers ------------------------------ #

    def _parse_saml_metadata_expiration(self, saml_metadata_document: str) -> datetime | None:
        """
        Parse the SAML metadata XML and extract the certificate expiration date.
        Returns the earliest expiration date if multiple certificates are present.
        """
        try:
            root = ET.fromstring(saml_metadata_document)

            # SAML metadata uses namespaces
            namespaces = {
                "md": "urn:oasis:names:tc:SAML:2.0:metadata",
                "ds": "http://www.w3.org/2000/09/xmldsig#",
            }

            # Find all X509Certificate elements
            cert_elements = root.findall(".//ds:X509Certificate", namespaces)

            if not cert_elements:
                return None

            expiration_dates = []
            for cert_elem in cert_elements:
                cert_pem = cert_elem.text
                if not cert_pem:
                    continue

                # Decode base64 certificate
                cert_der = base64.b64decode(cert_pem.strip())

                # Parse the X.509 certificate
                cert = x509.load_der_x509_certificate(cert_der)
                expiration_dates.append(cert.not_valid_after_utc)

            # Return the earliest expiration date
            if expiration_dates:
                return min(expiration_dates)

        except Exception as e:
            LOG.debug("Failed to parse SAML metadata for expiration date: ", e)

        return None

    def _get_saml_provider_arn(self, name: str, account_id: str, partition: str = "aws") -> str:
        """Generate an ARN for a SAML provider."""
        return f"arn:{partition}:iam::{account_id}:saml-provider/{name}"

    def _get_saml_provider_or_raise(
        self, saml_provider_arn: str, context: RequestContext
    ) -> SAMLProvider:
        """Get a SAML provider by ARN or raise NoSuchEntityException."""
        store = self._get_store(context)
        provider = store.SAML_PROVIDERS.get(saml_provider_arn)
        if not provider:
            raise NoSuchEntityException(f"SAMLProvider {saml_provider_arn} does not exist.")
        return provider

    def create_saml_provider(
        self,
        context: RequestContext,
        saml_metadata_document: SAMLMetadataDocumentType,
        name: SAMLProviderNameType,
        tags: tagListType | None = None,
        assertion_encryption_mode: assertionEncryptionModeType | None = None,
        add_private_key: privateKeyType | None = None,
        **kwargs,
    ) -> CreateSAMLProviderResponse:

        store = self._get_store(context)
        arn = self._get_saml_provider_arn(name, context.account_id, context.partition)

        if arn in store.SAML_PROVIDERS:
            raise InvalidInputException(f"SAMLProvider {name} already exists.")

        valid_until = self._parse_saml_metadata_expiration(saml_metadata_document)

        provider = SAMLProvider(
            arn=arn,
            name=name,
            saml_metadata_document=saml_metadata_document,
            create_date=datetime.now(UTC),
            valid_until=valid_until,
            tags=tags or [],
        )

        store.SAML_PROVIDERS[arn] = provider

        response = CreateSAMLProviderResponse(SAMLProviderArn=arn)
        if tags:
            response["Tags"] = tags
        return response

    def get_saml_provider(
        self, context: RequestContext, saml_provider_arn: arnType, **kwargs
    ) -> GetSAMLProviderResponse:
        provider = self._get_saml_provider_or_raise(saml_provider_arn, context)

        return GetSAMLProviderResponse(
            SAMLMetadataDocument=provider.saml_metadata_document,
            CreateDate=provider.create_date,
            ValidUntil=provider.valid_until,
            Tags=provider.tags if provider.tags else None,
        )

    def list_saml_providers(self, context: RequestContext, **kwargs) -> ListSAMLProvidersResponse:

        store = self._get_store(context)

        provider_list = [
            SAMLProviderListEntry(
                Arn=provider.arn,
                CreateDate=provider.create_date,
                ValidUntil=provider.valid_until,
            )
            for provider in store.SAML_PROVIDERS.values()
        ]

        return ListSAMLProvidersResponse(SAMLProviderList=provider_list)

    def update_saml_provider(
        self,
        context: RequestContext,
        saml_provider_arn: arnType,
        saml_metadata_document: SAMLMetadataDocumentType | None = None,
        assertion_encryption_mode: assertionEncryptionModeType | None = None,
        add_private_key: privateKeyType | None = None,
        remove_private_key: privateKeyIdType | None = None,
        **kwargs,
    ) -> UpdateSAMLProviderResponse:
        provider = self._get_saml_provider_or_raise(saml_provider_arn, context)

        if saml_metadata_document:
            provider.saml_metadata_document = saml_metadata_document
            provider.valid_until = self._parse_saml_metadata_expiration(saml_metadata_document)

        return UpdateSAMLProviderResponse(SAMLProviderArn=saml_provider_arn)

    def delete_saml_provider(
        self, context: RequestContext, saml_provider_arn: arnType, **kwargs
    ) -> None:
        store = self._get_store(context)

        if saml_provider_arn not in store.SAML_PROVIDERS:
            raise NoSuchEntityException(f"Manifest not found for arn {saml_provider_arn}")

        del store.SAML_PROVIDERS[saml_provider_arn]

    def tag_saml_provider(
        self,
        context: RequestContext,
        saml_provider_arn: arnType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        provider = self._get_saml_provider_or_raise(saml_provider_arn, context)

        # Merge tags: update existing keys, add new ones
        existing_keys = {tag["Key"]: i for i, tag in enumerate(provider.tags)}
        for tag in tags:
            key = tag["Key"]
            if key in existing_keys:
                provider.tags[existing_keys[key]] = tag
            else:
                provider.tags.append(tag)

    def untag_saml_provider(
        self,
        context: RequestContext,
        saml_provider_arn: arnType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        provider = self._get_saml_provider_or_raise(saml_provider_arn, context)
        provider.tags = [tag for tag in provider.tags if tag["Key"] not in tag_keys]

    def list_saml_provider_tags(
        self,
        context: RequestContext,
        saml_provider_arn: arnType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListSAMLProviderTagsResponse:
        provider = self._get_saml_provider_or_raise(saml_provider_arn, context)
        # TODO: Add pagination support with marker and max_items
        return ListSAMLProviderTagsResponse(Tags=provider.tags)

    # ------------------------------ SSH Public Keys ------------------------------ #

    def _generate_ssh_public_key_id(self, context: RequestContext) -> str:
        """
        Generate an SSH public key ID with APKA prefix.
        """
        return generate_iam_identifier(context.account_id, prefix="APKA", total_length=21)

    def _generate_ssh_key_fingerprint(self, ssh_public_key_body: str) -> str:
        """
        Generate a fingerprint for an SSH public key.
        The fingerprint is the MD5 hash of the key body in colon-separated hex format.
        """
        md5_hash = hashlib.md5(ssh_public_key_body.encode("utf-8")).hexdigest()
        return ":".join(md5_hash[i : i + 2] for i in range(0, len(md5_hash), 2))

    def upload_ssh_public_key(
        self,
        context: RequestContext,
        user_name: userNameType,
        ssh_public_key_body: publicKeyMaterialType,
        **kwargs,
    ) -> UploadSSHPublicKeyResponse:
        store = self._get_store(context)

        ssh_public_key_id = self._generate_ssh_public_key_id(context)
        fingerprint = self._generate_ssh_key_fingerprint(ssh_public_key_body)
        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            ssh_key = SSHPublicKey(
                UserName=user_name,
                SSHPublicKeyId=ssh_public_key_id,
                Fingerprint=fingerprint,
                SSHPublicKeyBody=ssh_public_key_body,
                Status=statusType.Active,
                UploadDate=datetime.now(),
            )

            user_entity.ssh_public_keys[ssh_public_key_id] = ssh_key

        return UploadSSHPublicKeyResponse(SSHPublicKey=ssh_key)

    def get_ssh_public_key(
        self,
        context: RequestContext,
        user_name: userNameType,
        ssh_public_key_id: publicKeyIdType,
        encoding: encodingType,
        **kwargs,
    ) -> GetSSHPublicKeyResponse:
        store = self._get_store(context)

        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)
            ssh_key = user_entity.ssh_public_keys.get(ssh_public_key_id)

            if not ssh_key:
                raise NoSuchEntityException(
                    f"The Public Key with id {ssh_public_key_id} cannot be found."
                )

        return GetSSHPublicKeyResponse(SSHPublicKey=ssh_key)

    def list_ssh_public_keys(
        self,
        context: RequestContext,
        user_name: userNameType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListSSHPublicKeysResponse:
        store = self._get_store(context)

        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            # Convert to metadata format (without SSHPublicKeyBody)
            ssh_keys_metadata = [
                SSHPublicKeyMetadata(
                    UserName=key["UserName"],
                    SSHPublicKeyId=key["SSHPublicKeyId"],
                    Status=key["Status"],
                    UploadDate=key["UploadDate"],
                )
                for key in user_entity.ssh_public_keys.values()
            ]

        return ListSSHPublicKeysResponse(SSHPublicKeys=ssh_keys_metadata)

    def update_ssh_public_key(
        self,
        context: RequestContext,
        user_name: userNameType,
        ssh_public_key_id: publicKeyIdType,
        status: statusType,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)
            ssh_key = user_entity.ssh_public_keys.get(ssh_public_key_id)

            if not ssh_key:
                raise NoSuchEntityException(
                    f"The Public Key with id {ssh_public_key_id} cannot be found."
                )

            ssh_key["Status"] = status

    def delete_ssh_public_key(
        self,
        context: RequestContext,
        user_name: userNameType,
        ssh_public_key_id: publicKeyIdType,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            if ssh_public_key_id not in user_entity.ssh_public_keys:
                raise NoSuchEntityException(
                    f"The Public Key with id {ssh_public_key_id} cannot be found."
                )

            del user_entity.ssh_public_keys[ssh_public_key_id]

    # ------------------------------ Server Certificates ------------------------------ #

    def _generate_server_certificate_id(self, context: RequestContext) -> str:
        """Generate a server certificate ID with ASCA prefix."""
        return generate_iam_identifier(context.account_id, prefix="ASCA", total_length=21)

    def _build_server_certificate_arn(
        self, context: RequestContext, path: str, cert_name: str
    ) -> str:
        """Build the ARN for a server certificate."""
        return (
            f"arn:{context.partition}:iam::{context.account_id}:server-certificate{path}{cert_name}"
        )

    def _get_server_certificate_entity(
        self, store: IamStore, cert_name: str
    ) -> ServerCertificateEntity:
        """Get a server certificate entity or raise NoSuchEntityException."""
        entity = store.SERVER_CERTIFICATES.get(cert_name)
        if not entity:
            raise NoSuchEntityException(
                f"The Server Certificate with name {cert_name} cannot be found."
            )
        return entity

    def upload_server_certificate(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        certificate_body: certificateBodyType,
        private_key: privateKeyType,
        path: pathType | None = None,
        certificate_chain: certificateChainType | None = None,
        tags: tagListType | None = None,
        **kwargs,
    ) -> UploadServerCertificateResponse:
        store = self._get_store(context)
        path = path or "/"

        # Validate tags
        self._validate_tags(tags, case_sensitive=False)

        # Check for duplicate name
        if server_certificate_name in store.SERVER_CERTIFICATES:
            raise EntityAlreadyExistsException(
                f"The Server Certificate with name {server_certificate_name} already exists."
            )

        # Parse certificate to extract expiration date
        expiration = None
        try:
            cert_data = certificate_body.encode("utf-8")
            cert = x509.load_pem_x509_certificate(cert_data)
            expiration = cert.not_valid_after_utc
        except Exception:
            # If parsing fails, we skip expiration extraction
            # AWS is more lenient here than for signing certificates
            pass

        # Generate ID and ARN
        cert_id = self._generate_server_certificate_id(context)
        cert_arn = self._build_server_certificate_arn(context, path, server_certificate_name)

        # Strip trailing whitespace from certificate body (AWS behavior)
        certificate_body = certificate_body.rstrip()
        if certificate_chain:
            certificate_chain = certificate_chain.rstrip()

        # Build metadata
        metadata = ServerCertificateMetadata(
            Path=path,
            ServerCertificateName=server_certificate_name,
            ServerCertificateId=cert_id,
            Arn=cert_arn,
            UploadDate=datetime.now(tz=UTC),
        )
        if expiration:
            metadata["Expiration"] = expiration

        # Create and store entity
        entity = ServerCertificateEntity(
            metadata=metadata,
            certificate_body=certificate_body,
            private_key=private_key,
            certificate_chain=certificate_chain,
            tags=tags or [],
        )
        store.SERVER_CERTIFICATES[server_certificate_name] = entity

        response = UploadServerCertificateResponse(ServerCertificateMetadata=metadata)
        if tags:
            response["Tags"] = tags
        return response

    def get_server_certificate(
        self, context: RequestContext, server_certificate_name: serverCertificateNameType, **kwargs
    ) -> GetServerCertificateResponse:
        store = self._get_store(context)
        entity = self._get_server_certificate_entity(store, server_certificate_name)

        # Build response - note: private key is NEVER returned
        cert = ServerCertificate(
            ServerCertificateMetadata=entity.metadata,
            CertificateBody=entity.certificate_body,
            Tags=entity.tags,  # AWS always returns Tags, even when empty
        )
        if entity.certificate_chain:
            cert["CertificateChain"] = entity.certificate_chain

        return GetServerCertificateResponse(ServerCertificate=cert)

    def list_server_certificates(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListServerCertificatesResponse:
        store = self._get_store(context)

        def _filter(metadata: ServerCertificateMetadata) -> bool:
            if path_prefix:
                return metadata.get("Path", "/").startswith(path_prefix)
            return True

        # Get all metadata sorted by name
        all_metadata = [entity.metadata for entity in store.SERVER_CERTIFICATES.values()]
        all_metadata.sort(key=lambda m: m.get("ServerCertificateName", ""))

        paginated_list = PaginatedList(all_metadata)

        def _token_generator(metadata: ServerCertificateMetadata) -> str:
            return metadata.get("ServerCertificateName")

        # Decode marker if provided
        if marker:
            marker = base64.b64decode(marker).decode("utf-8")

        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator,
            next_token=marker,
            page_size=max_items or 100,
            filter_function=_filter,
        )

        if next_marker:
            next_marker = base64.b64encode(next_marker.encode("utf-8")).decode("utf-8")
            return ListServerCertificatesResponse(
                ServerCertificateMetadataList=result, IsTruncated=True, Marker=next_marker
            )
        return ListServerCertificatesResponse(
            ServerCertificateMetadataList=result, IsTruncated=False
        )

    def delete_server_certificate(
        self, context: RequestContext, server_certificate_name: serverCertificateNameType, **kwargs
    ) -> None:
        store = self._get_store(context)
        # Validate exists (will raise NoSuchEntityException if not)
        self._get_server_certificate_entity(store, server_certificate_name)
        del store.SERVER_CERTIFICATES[server_certificate_name]

    def update_server_certificate(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        new_path: pathType | None = None,
        new_server_certificate_name: serverCertificateNameType | None = None,
        **kwargs,
    ) -> None:
        store = self._get_store(context)
        entity = self._get_server_certificate_entity(store, server_certificate_name)

        # Check if new name conflicts with existing certificate
        if new_server_certificate_name and new_server_certificate_name != server_certificate_name:
            if new_server_certificate_name in store.SERVER_CERTIFICATES:
                raise EntityAlreadyExistsException(
                    f"The Server Certificate with name {new_server_certificate_name} already exists."
                )

        # Update path if provided
        if new_path:
            entity.metadata["Path"] = new_path

        # Update name if provided
        target_name = new_server_certificate_name or server_certificate_name
        if new_server_certificate_name and new_server_certificate_name != server_certificate_name:
            entity.metadata["ServerCertificateName"] = new_server_certificate_name
            # Re-key in store
            del store.SERVER_CERTIFICATES[server_certificate_name]
            store.SERVER_CERTIFICATES[new_server_certificate_name] = entity

        # Update ARN
        path = entity.metadata.get("Path", "/")
        entity.metadata["Arn"] = self._build_server_certificate_arn(context, path, target_name)

    def tag_server_certificate(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        self._validate_tags(tags, case_sensitive=False)

        store = self._get_store(context)
        entity = self._get_server_certificate_entity(store, server_certificate_name)

        # Merge tags - update existing keys, add new ones (case-insensitive)
        existing_keys = {tag["Key"].lower(): i for i, tag in enumerate(entity.tags)}
        for tag in tags:
            key = tag["Key"].lower()
            if key in existing_keys:
                entity.tags[existing_keys[key]] = tag
            else:
                entity.tags.append(tag)

    def untag_server_certificate(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        self._validate_tag_keys(tag_keys)

        store = self._get_store(context)
        entity = self._get_server_certificate_entity(store, server_certificate_name)

        # Remove tags with matching keys (case-insensitive)
        tag_keys_set = {key.lower() for key in tag_keys}
        entity.tags = [tag for tag in entity.tags if tag["Key"].lower() not in tag_keys_set]

    def list_server_certificate_tags(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListServerCertificateTagsResponse:
        store = self._get_store(context)
        entity = self._get_server_certificate_entity(store, server_certificate_name)
        tags = list(entity.tags)

        # Sort alphabetically by key
        tags.sort(key=lambda k: k["Key"])

        paginated_list = PaginatedList(tags)

        def _token_generator(tag: Tag) -> str:
            return tag.get("Key")

        if marker:
            marker = base64.b64decode(marker).decode("utf-8")

        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator, next_token=marker, page_size=max_items or 100
        )

        if next_marker:
            next_marker = base64.b64encode(next_marker.encode("utf-8")).decode("utf-8")
            return ListServerCertificateTagsResponse(
                Tags=result, IsTruncated=True, Marker=next_marker
            )
        return ListServerCertificateTagsResponse(Tags=result, IsTruncated=False)

    # ------------------------------ Signing Certificates ------------------------------ #

    def _generate_signing_certificate_id(self) -> str:
        """Generate a 24-character signing certificate ID (uppercase alphanumeric)."""
        return "".join(random.choices(string.ascii_uppercase + string.digits, k=24))

    def upload_signing_certificate(
        self,
        context: RequestContext,
        certificate_body: certificateBodyType,
        user_name: existingUserNameType | None = None,
        **kwargs,
    ) -> UploadSigningCertificateResponse:
        store = self._get_store(context)

        # If no user_name provided, use the current user (caller)
        if not user_name:
            user_name = self._get_user_name_from_access_key_context(context)

        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            # Validate X.509 certificate format
            try:
                cert_data = certificate_body.encode("utf-8")
                x509.load_pem_x509_certificate(cert_data)
            except Exception:
                raise MalformedCertificateException(f"Certificate {certificate_body} is malformed.")

            # Check quota: max 2 signing certificates per user
            if len(user_entity.signing_certificates) >= 2:
                raise LimitExceededException("Cannot exceed quota for CertificatesPerUser: 2")

            # Generate certificate ID
            cert_id = self._generate_signing_certificate_id()

            # Create signing certificate
            signing_cert = SigningCertificate(
                UserName=user_name,
                CertificateId=cert_id,
                CertificateBody=certificate_body,
                Status="Active",
                UploadDate=datetime.now(tz=UTC),
            )

            user_entity.signing_certificates[cert_id] = signing_cert

        return UploadSigningCertificateResponse(Certificate=signing_cert)

    def list_signing_certificates(
        self,
        context: RequestContext,
        user_name: existingUserNameType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListSigningCertificatesResponse:
        store = self._get_store(context)

        # If no user_name provided, use the current user (caller)
        if not user_name:
            user_name = self._get_user_name_from_access_key_context(context)

        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)
            certs = list(user_entity.signing_certificates.values())

        # Sort by certificate ID
        certs.sort(key=lambda c: c.get("CertificateId", ""))

        paginated_list = PaginatedList(certs)

        def _token_generator(cert: SigningCertificate) -> str:
            return cert.get("CertificateId")

        if marker:
            marker = base64.b64decode(marker).decode("utf-8")

        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator, next_token=marker, page_size=max_items or 100
        )

        if next_marker:
            next_marker = base64.b64encode(next_marker.encode("utf-8")).decode("utf-8")
            return ListSigningCertificatesResponse(
                Certificates=result, IsTruncated=True, Marker=next_marker
            )
        return ListSigningCertificatesResponse(Certificates=result, IsTruncated=False)

    def update_signing_certificate(
        self,
        context: RequestContext,
        certificate_id: certificateIdType,
        status: statusType,
        user_name: existingUserNameType | None = None,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        # If no user_name provided, use the current user (caller)
        if not user_name:
            user_name = self._get_user_name_from_access_key_context(context)

        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            signing_cert = user_entity.signing_certificates.get(certificate_id)
            if not signing_cert:
                raise NoSuchEntityException(
                    f"The Certificate with id {certificate_id} cannot be found."
                )

            signing_cert["Status"] = status

    def delete_signing_certificate(
        self,
        context: RequestContext,
        certificate_id: certificateIdType,
        user_name: existingUserNameType | None = None,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        # If no user_name provided, use the current user (caller)
        if not user_name:
            user_name = self._get_user_name_from_access_key_context(context)

        with self._user_lock:
            user_entity = self._get_user_entity(store, user_name)

            if certificate_id not in user_entity.signing_certificates:
                raise NoSuchEntityException(
                    f"The Certificate with id {certificate_id} cannot be found."
                )

            del user_entity.signing_certificates[certificate_id]

    # ------------------------------ OIDC Providers ------------------------------ #

    def _get_oidc_provider_arn(self, url: str, account_id: str, partition: str = "aws") -> str:
        """
        Generate an ARN for an OIDC provider.
        The ARN uses the URL host (without protocol) as the resource identifier.
        """
        # Remove protocol prefix if present
        host = url
        if host.startswith("https://"):
            host = host[8:]
        elif host.startswith("http://"):
            host = host[7:]
        # Remove trailing slash
        host = host.rstrip("/")
        return f"arn:{partition}:iam::{account_id}:oidc-provider/{host}"

    def _get_oidc_provider_or_raise(
        self, oidc_provider_arn: str, context: RequestContext
    ) -> OIDCProvider:
        """Get an OIDC provider by ARN or raise NoSuchEntityException."""
        store = self._get_store(context)
        provider = store.OIDC_PROVIDERS.get(oidc_provider_arn)
        if not provider:
            raise NoSuchEntityException(
                f"OpenIDConnect Provider not found for arn {oidc_provider_arn}"
            )
        return provider

    def create_open_id_connect_provider(
        self,
        context: RequestContext,
        url: OpenIDConnectProviderUrlType,
        client_id_list: clientIDListType | None = None,
        thumbprint_list: thumbprintListType | None = None,
        tags: tagListType | None = None,
        **kwargs,
    ) -> CreateOpenIDConnectProviderResponse:
        # Validate URL, thumbprint, and client ID constraints
        validation_errors = []

        if url and len(url) > 255:
            validation_errors.append(
                "Value at 'url' failed to satisfy constraint: "
                "Member must have length less than or equal to 255"
            )

        if thumbprint_list:
            for thumbprint in thumbprint_list:
                if len(thumbprint) != 40:
                    validation_errors.append(
                        "Value at 'thumbprintList' failed to satisfy constraint: "
                        "Member must satisfy constraint: [Member must have length less than or equal to 40, "
                        "Member must have length greater than or equal to 40]"
                    )
                    break

        if client_id_list:
            for client_id in client_id_list:
                if len(client_id) > 255 or len(client_id) < 1:
                    validation_errors.append(
                        "Value at 'clientIDList' failed to satisfy constraint: "
                        "Member must satisfy constraint: [Member must have length less than or equal to 255, "
                        "Member must have length greater than or equal to 1]"
                    )
                    break

        if validation_errors:
            raise ValidationListError(validation_errors)

        # Validate URL format (must start with https://)
        if not url or not url.startswith("https://"):
            raise ValidationError("Invalid Open ID Connect Provider URL")

        # Validate thumbprint list limit (max 5)
        if thumbprint_list and len(thumbprint_list) > 5:
            raise InvalidInputException("Thumbprint list must contain fewer than 5 entries.")

        # Validate client ID list limit (max 100)
        if client_id_list and len(client_id_list) > 100:
            raise LimitExceededException(
                "Cannot exceed quota for ClientIdsPerOpenIdConnectProvider: 100"
            )

        # Validate tag limit (max 50)
        if tags and len(tags) > 50:
            raise LimitExceededException("The number of tags has reached the maximum limit.")

        store = self._get_store(context)
        arn = self._get_oidc_provider_arn(url, context.account_id, context.partition)

        # Check for duplicate provider
        if arn in store.OIDC_PROVIDERS:
            raise EntityAlreadyExistsException(f"Provider with url {url} already exists.")

        provider = OIDCProvider(
            arn=arn,
            url=url,
            create_date=datetime.now(UTC),
            client_id_list=client_id_list or [],
            thumbprint_list=thumbprint_list or [],
            tags=tags or [],
        )

        store.OIDC_PROVIDERS[arn] = provider

        response = CreateOpenIDConnectProviderResponse(OpenIDConnectProviderArn=arn)
        if tags:
            response["Tags"] = tags
        return response

    def get_open_id_connect_provider(
        self, context: RequestContext, open_id_connect_provider_arn: arnType, **kwargs
    ) -> GetOpenIDConnectProviderResponse:
        provider = self._get_oidc_provider_or_raise(open_id_connect_provider_arn, context)

        return GetOpenIDConnectProviderResponse(
            Url=provider.url,
            ClientIDList=provider.client_id_list if provider.client_id_list else None,
            ThumbprintList=provider.thumbprint_list if provider.thumbprint_list else None,
            CreateDate=provider.create_date,
            Tags=provider.tags if provider.tags else None,
        )

    def list_open_id_connect_providers(
        self, context: RequestContext, **kwargs
    ) -> ListOpenIDConnectProvidersResponse:
        store = self._get_store(context)

        provider_list = [
            OpenIDConnectProviderListEntry(Arn=provider.arn)
            for provider in store.OIDC_PROVIDERS.values()
        ]

        return ListOpenIDConnectProvidersResponse(OpenIDConnectProviderList=provider_list)

    def delete_open_id_connect_provider(
        self, context: RequestContext, open_id_connect_provider_arn: arnType, **kwargs
    ) -> None:
        store = self._get_store(context)

        if open_id_connect_provider_arn not in store.OIDC_PROVIDERS:
            raise NoSuchEntityException(
                f"OpenId connect Provider {open_id_connect_provider_arn} cannot be found."
            )

        del store.OIDC_PROVIDERS[open_id_connect_provider_arn]

    def add_client_id_to_open_id_connect_provider(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        client_id: clientIDType,
        **kwargs,
    ) -> None:
        provider = self._get_oidc_provider_or_raise(open_id_connect_provider_arn, context)

        if client_id not in provider.client_id_list:
            provider.client_id_list.append(client_id)

    def remove_client_id_from_open_id_connect_provider(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        client_id: clientIDType,
        **kwargs,
    ) -> None:
        provider = self._get_oidc_provider_or_raise(open_id_connect_provider_arn, context)

        if client_id in provider.client_id_list:
            provider.client_id_list.remove(client_id)
        else:
            raise NoSuchEntityException(f"Client ID {client_id} not found.")

    def update_open_id_connect_provider_thumbprint(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        thumbprint_list: thumbprintListType,
        **kwargs,
    ) -> None:
        provider = self._get_oidc_provider_or_raise(open_id_connect_provider_arn, context)
        provider.thumbprint_list = thumbprint_list

    def tag_open_id_connect_provider(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        provider = self._get_oidc_provider_or_raise(open_id_connect_provider_arn, context)

        # Calculate how many new tags would be added
        existing_keys = {tag["Key"]: i for i, tag in enumerate(provider.tags)}
        new_tag_count = sum(1 for tag in tags if tag["Key"] not in existing_keys)

        # Check tag limit (max 50 tags)
        if len(provider.tags) + new_tag_count > 50:
            raise LimitExceededException("The number of tags has reached the maximum limit.")

        # Merge tags: update existing keys, add new ones
        for tag in tags:
            key = tag["Key"]
            if key in existing_keys:
                provider.tags[existing_keys[key]] = tag
            else:
                provider.tags.append(tag)

    def untag_open_id_connect_provider(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        provider = self._get_oidc_provider_or_raise(open_id_connect_provider_arn, context)
        provider.tags = [tag for tag in provider.tags if tag["Key"] not in tag_keys]

    def list_open_id_connect_provider_tags(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListOpenIDConnectProviderTagsResponse:
        provider = self._get_oidc_provider_or_raise(open_id_connect_provider_arn, context)

        paginated_list = PaginatedList(provider.tags)

        def _token_generator(tag: Tag) -> str:
            return tag.get("Key")

        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator, next_token=marker, page_size=max_items or 100
        )

        if next_marker:
            return ListOpenIDConnectProviderTagsResponse(
                Tags=result,
                IsTruncated=True,
                Marker=next_marker,
            )
        else:
            return ListOpenIDConnectProviderTagsResponse(Tags=result, IsTruncated=False)

    # ------------------------------ Instance Profile Operations ------------------------------ #

    def _get_instance_profile_entity(
        self, store: IamStore, instance_profile_name: str
    ) -> InstanceProfileEntity:
        """Gets the instance profile entity and raises the right exception if not found."""
        entity = store.INSTANCE_PROFILES.get(instance_profile_name)
        if not entity:
            raise NoSuchEntityException(
                f"Instance Profile {instance_profile_name} cannot be found."
            )
        return entity

    def _generate_instance_profile_id(self, context: RequestContext) -> str:
        """Generate an instance profile ID: AIPA + 17 random chars."""
        return generate_iam_identifier(context.account_id, prefix="AIPA", total_length=21)

    def _build_instance_profile_arn(
        self, context: RequestContext, path: str, profile_name: str
    ) -> str:
        """Build the ARN for an instance profile."""
        partition = get_partition(context.region)
        # Remove leading slash from path if present to avoid double slashes
        path_part = path.rstrip("/")
        if path_part == "":
            return f"arn:{partition}:iam::{context.account_id}:instance-profile/{profile_name}"
        return (
            f"arn:{partition}:iam::{context.account_id}:instance-profile{path_part}/{profile_name}"
        )

    def _build_role_for_instance_profile(self, role_entity: RoleEntity) -> Role:
        """Build a Role object suitable for inclusion in an InstanceProfile response."""
        role = role_entity.role
        # Return a subset of role fields for instance profile responses
        return Role(
            Path=role.get("Path", "/"),
            RoleName=role.get("RoleName"),
            RoleId=role.get("RoleId"),
            Arn=role.get("Arn"),
            CreateDate=role.get("CreateDate"),
            AssumeRolePolicyDocument=role.get("AssumeRolePolicyDocument"),
        )

    def _get_profiles_for_role(self, store: IamStore, role_name: str) -> list[InstanceProfile]:
        """
        Gets all instance profiles the given role is a part of
        :param store: IamStore to check
        :param role_name: Role name
        :return: Instance Profiles with the given attached role
        """
        role_entity = self._get_role_entity(store, role_name)

        profiles = []
        for entity in store.INSTANCE_PROFILES.values():
            if entity.role_name == role_name:
                response_profile = entity.instance_profile.copy()
                response_profile["Roles"] = [self._build_role_for_instance_profile(role_entity)]
                profiles.append(response_profile)
        return profiles

    @handler("CreateInstanceProfile")
    def create_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        path: pathType | None = None,
        tags: tagListType | None = None,
        **kwargs,
    ) -> CreateInstanceProfileResponse:
        store = self._get_store(context)
        path = path or "/"

        with self._instance_profile_lock:
            # Check for duplicate
            if instance_profile_name in store.INSTANCE_PROFILES:
                raise EntityAlreadyExistsException(
                    f"Instance Profile {instance_profile_name} already exists."
                )

            # Generate ID and ARN
            profile_id = self._generate_instance_profile_id(context)
            profile_arn = self._build_instance_profile_arn(context, path, instance_profile_name)

            # Build the InstanceProfile object
            instance_profile = InstanceProfile(
                Path=path,
                InstanceProfileName=instance_profile_name,
                InstanceProfileId=profile_id,
                Arn=profile_arn,
                CreateDate=datetime.now(UTC),
                Roles=[],
            )

            # Add tags if provided
            if tags:
                instance_profile["Tags"] = tags

            # Store the entity
            entity = InstanceProfileEntity(instance_profile=instance_profile)
            store.INSTANCE_PROFILES[instance_profile_name] = entity

        return CreateInstanceProfileResponse(InstanceProfile=instance_profile)

    @handler("GetInstanceProfile")
    def get_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        **kwargs,
    ) -> GetInstanceProfileResponse:
        store = self._get_store(context)

        with self._instance_profile_lock:
            entity = self._get_instance_profile_entity(store, instance_profile_name)
            profile = entity.instance_profile.copy()

            # Add role if attached
            if entity.role_name:
                role_entity = store.ROLES.get(entity.role_name)
                if role_entity:
                    profile["Roles"] = [self._build_role_for_instance_profile(role_entity)]
                else:
                    profile["Roles"] = []
            else:
                profile["Roles"] = []

            # Ensure Tags is present (AWS always returns it)
            if "Tags" not in profile:
                profile["Tags"] = []

        return GetInstanceProfileResponse(InstanceProfile=profile)

    @handler("DeleteInstanceProfile")
    def delete_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        with self._instance_profile_lock:
            entity = self._get_instance_profile_entity(store, instance_profile_name)

            # Check if profile has a role attached
            if entity.role_name:
                raise DeleteConflictException(
                    "Cannot delete entity, must remove roles from instance profile first."
                )

            del store.INSTANCE_PROFILES[instance_profile_name]

    @handler("ListInstanceProfiles")
    def list_instance_profiles(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListInstanceProfilesResponse:
        store = self._get_store(context)
        path_prefix = path_prefix or "/"

        with self._instance_profile_lock:
            profiles = []
            for entity in store.INSTANCE_PROFILES.values():
                profile = entity.instance_profile
                # Filter by path prefix
                if not profile.get("Path", "/").startswith(path_prefix):
                    continue

                # Build response profile with role
                response_profile = profile.copy()
                if entity.role_name:
                    role_entity = store.ROLES.get(entity.role_name)
                    if role_entity:
                        response_profile["Roles"] = [
                            self._build_role_for_instance_profile(role_entity)
                        ]
                    else:
                        response_profile["Roles"] = []
                else:
                    response_profile["Roles"] = []

                profiles.append(response_profile)

        # Sort by name for consistent ordering
        profiles.sort(key=lambda p: p.get("InstanceProfileName", "").lower())

        # TODO: Add pagination support
        return ListInstanceProfilesResponse(InstanceProfiles=profiles, IsTruncated=False)

    @handler("AddRoleToInstanceProfile")
    def add_role_to_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        role_name: roleNameType,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        with self._instance_profile_lock:
            # Validate instance profile exists
            entity = self._get_instance_profile_entity(store, instance_profile_name)

            # Validate role exists
            role_entity = store.ROLES.get(role_name)
            if not role_entity:
                raise NoSuchEntityException(f"The role with name {role_name} cannot be found.")

            # Check if profile already has a role (AWS limits to 1 role per profile)
            if entity.role_name:
                raise LimitExceededException(
                    "Cannot exceed quota for InstanceSessionsPerInstanceProfile: 1"
                )

            # Attach the role
            entity.role_name = role_name

    @handler("RemoveRoleFromInstanceProfile")
    def remove_role_from_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        role_name: roleNameType,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        with self._instance_profile_lock:
            # Validate instance profile exists
            entity = self._get_instance_profile_entity(store, instance_profile_name)

            # Validate role exists
            role_entity = store.ROLES.get(role_name)
            if not role_entity:
                raise NoSuchEntityException(f"The role with name {role_name} cannot be found.")

            # Check if the role is actually attached to this profile
            if entity.role_name != role_name:
                raise NoSuchEntityException(
                    f"Role {role_name} in Instance Profile {instance_profile_name} cannot be found."
                )

            # Remove the role
            entity.role_name = None

    @handler("ListInstanceProfilesForRole")
    def list_instance_profiles_for_role(
        self,
        context: RequestContext,
        role_name: roleNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListInstanceProfilesForRoleResponse:
        store = self._get_store(context)

        with self._instance_profile_lock, self._role_lock:
            profiles = self._get_profiles_for_role(store, role_name)

        # Sort by name for consistent ordering
        profiles.sort(key=lambda p: p.get("InstanceProfileName", "").lower())

        # TODO: Add pagination support
        return ListInstanceProfilesForRoleResponse(InstanceProfiles=profiles, IsTruncated=False)

    @handler("TagInstanceProfile")
    def tag_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        with self._instance_profile_lock:
            entity = self._get_instance_profile_entity(store, instance_profile_name)
            profile = entity.instance_profile

            # Initialize tags if not present
            if "Tags" not in profile:
                profile["Tags"] = []

            existing_tags = profile["Tags"]

            # Update or add tags
            for new_tag in tags:
                key = new_tag.get("Key")
                # Check if tag with this key already exists
                found = False
                for existing_tag in existing_tags:
                    if existing_tag.get("Key") == key:
                        existing_tag["Value"] = new_tag.get("Value")
                        found = True
                        break
                if not found:
                    existing_tags.append(new_tag)

    @handler("UntagInstanceProfile")
    def untag_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        with self._instance_profile_lock:
            entity = self._get_instance_profile_entity(store, instance_profile_name)
            profile = entity.instance_profile

            if "Tags" not in profile:
                return

            # Remove tags with matching keys
            profile["Tags"] = [tag for tag in profile["Tags"] if tag.get("Key") not in tag_keys]

    @handler("ListInstanceProfileTags")
    def list_instance_profile_tags(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListInstanceProfileTagsResponse:
        store = self._get_store(context)

        with self._instance_profile_lock:
            entity = self._get_instance_profile_entity(store, instance_profile_name)
            profile = entity.instance_profile
            tags = profile.get("Tags", [])

        # TODO: Add pagination support
        return ListInstanceProfileTagsResponse(Tags=tags, IsTruncated=False)

    # ------------------------------ Virtual MFA Devices ------------------------------ #

    def _generate_mfa_serial_number(
        self, name: str, path: str, account_id: str, partition: str = "aws"
    ) -> str:
        """
        Generate a serial number (ARN) for a virtual MFA device.
        Format: arn:{partition}:iam::{account_id}:mfa/{path_resource}{name}
        """
        # Path "/" becomes empty in the ARN, other paths have leading slash stripped
        if path == "/":
            path_resource = ""
        else:
            path_resource = path[1:]  # Remove leading slash, keep trailing slash
        return f"arn:{partition}:iam::{account_id}:mfa/{path_resource}{name}"

    def _generate_totp_secret(self) -> bytes:
        """Generate a random Base32-encoded secret for TOTP."""
        # Generate 20 random bytes (160 bits) for the secret
        secret_bytes = bytes(random.getrandbits(8) for _ in range(20))
        # Base32 encode it
        return base64.b32encode(secret_bytes)

    def _generate_qr_code_png(self, secret: bytes, device_name: str, account_id: str) -> bytes:
        """
        Generate a QR code PNG for the virtual MFA device.
        In a real implementation, this would generate an actual QR code image.
        For LocalStack, we return a minimal placeholder PNG.
        """
        # Minimal valid PNG (1x1 transparent pixel)
        # This is a placeholder - real AWS returns an actual QR code
        return base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
        )

    def _validate_mfa_path(self, path: str | None) -> str:
        """Validate and return the MFA device path."""
        if path is None:
            return "/"

        # Check path length
        if len(path) > 512:
            raise ValidationListError(
                [
                    "Value at 'path' failed to satisfy constraint: "
                    "Member must have length less than or equal to 512"
                ]
            )

        # Path must start and end with /
        if not path.startswith("/") or not path.endswith("/"):
            raise ValidationError(
                "The specified value for path is invalid. It must begin and end with / "
                "and contain only alphanumeric characters and/or / characters."
            )

        return path

    def create_virtual_mfa_device(
        self,
        context: RequestContext,
        virtual_mfa_device_name: virtualMFADeviceName,
        path: pathType | None = None,
        tags: tagListType | None = None,
        **kwargs,
    ) -> CreateVirtualMFADeviceResponse:
        # Validate path
        validated_path = self._validate_mfa_path(path)

        store = self._get_store(context)
        serial_number = self._generate_mfa_serial_number(
            virtual_mfa_device_name, validated_path, context.account_id, context.partition
        )

        # Check for duplicate device
        if serial_number in store.MFA_DEVICES:
            raise EntityAlreadyExistsException("MFA device already exists.")

        # Generate TOTP secret and QR code
        base32_secret = self._generate_totp_secret()
        qr_code_png = self._generate_qr_code_png(
            base32_secret, virtual_mfa_device_name, context.account_id
        )

        # Create the device model
        device_model = VirtualMFADeviceModel(
            SerialNumber=serial_number,
            Base32StringSeed=base32_secret,
            QRCodePNG=qr_code_png,
            Tags=tags or [],
        )

        store.MFA_DEVICES[serial_number] = MFADeviceEntity(
            device=device_model, device_name=device_model, path=path
        )

        # Build response
        virtual_mfa_device = VirtualMFADevice(
            SerialNumber=serial_number,
            Base32StringSeed=base32_secret,
            QRCodePNG=qr_code_png,
        )

        return CreateVirtualMFADeviceResponse(VirtualMFADevice=virtual_mfa_device)

    def delete_virtual_mfa_device(
        self,
        context: RequestContext,
        serial_number: serialNumberType,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        if serial_number not in store.MFA_DEVICES:
            raise NoSuchEntityException(
                f"MFA Device with serial number {serial_number} does not exist."
            )

        # If device is assigned to a user, remove it from the user's MFA devices
        device = store.MFA_DEVICES[serial_number]
        if device.user_name:
            user_entity = store.USERS[device.user_name]
            user_entity.mfa_devices.remove(serial_number)

        del store.MFA_DEVICES[serial_number]

    def list_virtual_mfa_devices(
        self,
        context: RequestContext,
        assignment_status: assignmentStatusType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListVirtualMFADevicesResponse:
        store = self._get_store(context)

        # Get all virtual MFA devices (those with QRCodePNG)
        all_devices = [d for d in store.MFA_DEVICES.values() if "QRCodePNG" in d.device]

        # Filter by assignment status
        if assignment_status == "Assigned":
            all_devices = [d for d in all_devices if d.user_name is not None]
        elif assignment_status == "Unassigned":
            all_devices = [d for d in all_devices if d.user_name is None]
        # "Any" or None means no filtering

        # Sort by serial number for consistent ordering
        all_devices.sort(key=lambda d: d.device.get("SerialNumber", ""))

        # Convert to response format
        def _map_to_response(device: MFADeviceEntity) -> VirtualMFADevice:
            vmd = VirtualMFADevice(SerialNumber=device.device.get("SerialNumber"))
            if device.user_name:
                vmd["User"] = store.USERS[device.user_name].user
                # Include EnableDate for assigned devices
                if "EnableDate" in device.device:
                    vmd["EnableDate"] = device.device["EnableDate"]
            return vmd

        response_devices = [_map_to_response(d) for d in all_devices]

        # Validate marker if provided
        if marker:
            valid_markers = [d.get("SerialNumber") for d in response_devices]
            if marker not in valid_markers:
                raise ValidationError("Invalid Marker.")

        paginated_list = PaginatedList(response_devices)

        def _token_generator(vmd: VirtualMFADevice) -> str:
            return vmd.get("SerialNumber", "")

        result, next_marker = paginated_list.get_page(
            token_generator=_token_generator,
            next_token=marker,
            page_size=max_items or 100,
        )

        response = ListVirtualMFADevicesResponse(
            VirtualMFADevices=result,
            IsTruncated=next_marker is not None,
        )

        if next_marker:
            response["Marker"] = next_marker

        return response

    def enable_mfa_device(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        serial_number: serialNumberType,
        authentication_code1: authenticationCodeType,
        authentication_code2: authenticationCodeType,
        **kwargs,
    ) -> None:
        # Verify user exists
        user_entity = self._get_user_or_raise_error(user_name, context)

        store = self._get_store(context)
        enable_date = datetime.now(UTC)

        if serial_number in store.MFA_DEVICES:
            # Virtual MFA device - check if already attached to another user
            device = store.MFA_DEVICES[serial_number]
            if device.user_name is not None:
                raise EntityAlreadyExistsException("MFA Device is already in use.")
            device.device["EnableDate"] = enable_date
            device.user_name = user_name
        else:
            # Physical token MFA - create new entry
            mfa_device = MFADevice(
                SerialNumber=serial_number,
                EnableDate=enable_date,
            )
            device = MFADeviceEntity(
                device_name=serial_number,
                path="/",
                device=mfa_device,
                user_name=user_name,
            )
            store.MFA_DEVICES[serial_number] = device

        user_entity.mfa_devices.append(serial_number)

    def deactivate_mfa_device(
        self,
        context: RequestContext,
        serial_number: serialNumberType,
        user_name: existingUserNameType | None = None,
        **kwargs,
    ) -> None:
        store = self._get_store(context)

        if serial_number not in store.MFA_DEVICES:
            raise NoSuchEntityException(
                f"MFA Device with serial number {serial_number} does not exist."
            )

        device = store.MFA_DEVICES[serial_number]
        device.device["EnableDate"] = None
        device.user_name = None

        user_entity = self._get_user_or_raise_error(user_name, context)
        user_entity.mfa_devices.remove(serial_number)

    def list_mfa_devices(
        self,
        context: RequestContext,
        user_name: existingUserNameType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListMFADevicesResponse:
        # TODO extract user_name from keys if it's not passed

        user_entity = self._get_user_or_raise_error(user_name, context)
        store = self._get_store(context)

        mfa_serial_numbers = user_entity.mfa_devices
        all_mfa_devices = [
            store.MFA_DEVICES[serial]
            for serial in mfa_serial_numbers
            if serial in store.MFA_DEVICES
        ]

        # Convert to response format
        mfa_devices = [
            MFADevice(
                UserName=device.user_name or user_name,
                SerialNumber=device.device.get("SerialNumber"),
                EnableDate=device.device.get("EnableDate"),
            )
            for device in all_mfa_devices
        ]

        # TODO: Add pagination support with marker and max_items
        return ListMFADevicesResponse(
            MFADevices=mfa_devices,
            IsTruncated=False,
        )

    # ------------------------------ Account Summary ------------------------------ #

    def get_account_summary(self, context: RequestContext, **kwargs) -> GetAccountSummaryResponse:
        """Return summary metrics about IAM entities and quotas."""
        store = self._get_store(context)

        # Count dynamic values from store
        users_count = len(store.USERS)
        groups_count = len(store.GROUPS)
        roles_count = len(store.ROLES)
        policies_count = len(store.MANAGED_POLICIES)
        instance_profiles_count = len(store.INSTANCE_PROFILES)
        server_certificates_count = len(store.SERVER_CERTIFICATES)

        # Count MFA devices
        mfa_devices_count = len(store.MFA_DEVICES)
        mfa_devices_in_use = sum(1 for d in store.MFA_DEVICES.values() if d.user_name is not None)

        # Count providers (SAML + OIDC)
        providers_count = len(store.SAML_PROVIDERS) + len(store.OIDC_PROVIDERS)

        # Count policy versions in use (each policy has at least 1 version)
        policy_versions_in_use = sum(
            len(entity.versions) for entity in store.MANAGED_POLICIES.values()
        )

        # Account password present is 1 if PASSWORD_POLICY exists
        account_password_present = 1 if store.PASSWORD_POLICY else 0

        # Build summary map with fixed quotas and dynamic counts
        summary_map = {
            # Dynamic counts
            "Users": users_count,
            "Groups": groups_count,
            "Roles": roles_count,
            "Policies": policies_count,
            "InstanceProfiles": instance_profiles_count,
            "ServerCertificates": server_certificates_count,
            "MFADevices": mfa_devices_count,
            "MFADevicesInUse": mfa_devices_in_use,
            "Providers": providers_count,
            "PolicyVersionsInUse": policy_versions_in_use,
            "AccountPasswordPresent": account_password_present,
            # These are typically 0 for standard accounts (not checking root user)
            "AccountMFAEnabled": 0,
            "AccountAccessKeysPresent": 0,
            "AccountSigningCertificatesPresent": 0,
            # Fixed quotas (AWS defaults)
            "UsersQuota": 5000,
            "GroupsQuota": 300,
            "RolesQuota": 1000,
            "PoliciesQuota": 1500,
            "InstanceProfilesQuota": 1000,
            "ServerCertificatesQuota": 20,
            "PolicyVersionsInUseQuota": 10000,
            "PolicySizeQuota": 6144,
            "VersionsPerPolicyQuota": 5,
            "GroupsPerUserQuota": 10,
            "SigningCertificatesPerUserQuota": 2,
            "AccessKeysPerUserQuota": 2,
            "AttachedPoliciesPerGroupQuota": 10,
            "AttachedPoliciesPerRoleQuota": 10,
            "AttachedPoliciesPerUserQuota": 10,
            "UserPolicySizeQuota": 2048,
            "GroupPolicySizeQuota": 5120,
            "RolePolicySizeQuota": 10240,
            "AssumeRolePolicySizeQuota": 2048,
            "GlobalEndpointTokenVersion": 1,
        }

        return GetAccountSummaryResponse(SummaryMap=summary_map)

    # ------------------------------ Account Authorization Details ------------------------------ #

    def _build_role_detail(self, store: IamStore, role_entity: RoleEntity) -> RoleDetail:
        """Convert RoleEntity to RoleDetail for authorization details response."""
        role = role_entity.role

        role_policy_list = [
            PolicyDetail(
                PolicyName=name,
                PolicyDocument=doc,
            )
            for name, doc in role_entity.inline_policies.items()
        ]

        # Build attached managed policies list
        attached_managed_policies = [
            AttachedPolicy(
                PolicyName=arn.split("/")[-1],
                PolicyArn=arn,
            )
            for arn in role_entity.attached_policy_arns
        ]

        # Get instance profiles for this role
        instance_profile_list = []
        for ip_entity in store.INSTANCE_PROFILES.values():
            if ip_entity.role_name == role.get("RoleName"):
                # Build the instance profile with the role attached
                ip = ip_entity.instance_profile.copy()
                ip["Roles"] = [self._build_role_for_instance_profile(role_entity)]
                instance_profile_list.append(ip)

        # AssumeRolePolicyDocument should be a JSON string (boto3 decodes it client-side)
        assume_role_doc = role.get("AssumeRolePolicyDocument", "{}")
        if assume_role_doc:
            assume_role_doc = assume_role_doc

        detail = RoleDetail(
            Path=role.get("Path", "/"),
            RoleName=role.get("RoleName"),
            RoleId=role.get("RoleId"),
            Arn=role.get("Arn"),
            CreateDate=role.get("CreateDate"),
            AssumeRolePolicyDocument=assume_role_doc,
            RolePolicyList=role_policy_list,
            AttachedManagedPolicies=attached_managed_policies,
            InstanceProfileList=instance_profile_list,
            Tags=role.get("Tags", []),
            RoleLastUsed=role.get("RoleLastUsed", {}),
        )

        # Add permissions boundary if present
        if "PermissionsBoundary" in role:
            detail["PermissionsBoundary"] = role["PermissionsBoundary"]

        return detail

    def _build_user_detail(self, store: IamStore, user_entity: UserEntity) -> UserDetail:
        """Convert UserEntity to UserDetail for authorization details response."""
        user = user_entity.user

        # Build inline policies list
        # PolicyDocument should be a JSON string (boto3 decodes it client-side)
        user_policy_list = [
            PolicyDetail(
                PolicyName=name,
                PolicyDocument=doc,
            )
            for name, doc in user_entity.inline_policies.items()
        ]

        # Build attached managed policies list
        attached_managed_policies = [
            AttachedPolicy(
                PolicyName=arn.split("/")[-1],
                PolicyArn=arn,
            )
            for arn in user_entity.attached_policy_arns
        ]

        # Get groups this user belongs to
        group_list = []
        for group_entity in store.GROUPS.values():
            if user.get("UserName") in group_entity.member_user_names:
                group_list.append(group_entity.group.get("GroupName"))

        detail = UserDetail(
            Path=user.get("Path", "/"),
            UserName=user.get("UserName"),
            UserId=user.get("UserId"),
            Arn=user.get("Arn"),
            CreateDate=user.get("CreateDate"),
            AttachedManagedPolicies=attached_managed_policies,
            GroupList=group_list,
            Tags=user.get("Tags", []),
        )

        # Only include UserPolicyList if there are inline policies (AWS behavior)
        if user_policy_list:
            detail["UserPolicyList"] = user_policy_list

        # Add permissions boundary if present
        if "PermissionsBoundary" in user:
            detail["PermissionsBoundary"] = user["PermissionsBoundary"]

        return detail

    def _build_group_detail(self, store: IamStore, group_entity: GroupEntity) -> GroupDetail:
        """Convert GroupEntity to GroupDetail for authorization details response."""
        group = group_entity.group

        # Build inline policies list
        # PolicyDocument should be a JSON string (boto3 decodes it client-side)
        group_policy_list = [
            PolicyDetail(
                PolicyName=name,
                PolicyDocument=doc,
            )
            for name, doc in group_entity.inline_policies.items()
        ]

        # Build attached managed policies list
        attached_managed_policies = [
            AttachedPolicy(
                PolicyName=arn.split("/")[-1],
                PolicyArn=arn,
            )
            for arn in group_entity.attached_policy_arns
        ]

        return GroupDetail(
            Path=group.get("Path", "/"),
            GroupName=group.get("GroupName"),
            GroupId=group.get("GroupId"),
            Arn=group.get("Arn"),
            CreateDate=group.get("CreateDate"),
            GroupPolicyList=group_policy_list,
            AttachedManagedPolicies=attached_managed_policies,
        )

    def _build_managed_policy_detail(
        self, policy_entity: ManagedPolicyEntity
    ) -> ManagedPolicyDetail:
        """Convert ManagedPolicyEntity to ManagedPolicyDetail for authorization details response."""
        policy = policy_entity.policy

        # Build policy version list with documents
        # Document should be a JSON string (boto3 decodes it client-side)
        policy_version_list = []
        for version_id, version in policy_entity.versions.items():
            version = PolicyVersion(version)
            policy_version_list.append(version)

        return ManagedPolicyDetail(
            PolicyName=policy.get("PolicyName"),
            PolicyId=policy.get("PolicyId"),
            Arn=policy.get("Arn"),
            Path=policy.get("Path", "/"),
            DefaultVersionId=policy.get("DefaultVersionId"),
            AttachmentCount=policy.get("AttachmentCount", 0),
            PermissionsBoundaryUsageCount=policy.get("PermissionsBoundaryUsageCount", 0),
            IsAttachable=policy.get("IsAttachable", True),
            Description=policy.get("Description"),
            CreateDate=policy.get("CreateDate"),
            UpdateDate=policy.get("UpdateDate"),
            PolicyVersionList=policy_version_list,
        )

    def get_account_authorization_details(
        self,
        context: RequestContext,
        filter: entityListType = None,
        max_items: maxItemsType = None,
        marker: markerType = None,
        **kwargs,
    ) -> GetAccountAuthorizationDetailsResponse:
        """Return detailed information about all IAM entities for authorization review."""
        store = self._get_store(context)

        # Determine which entity types to include
        include_roles = filter is None or EntityType.Role in filter
        include_users = filter is None or EntityType.User in filter
        include_groups = filter is None or EntityType.Group in filter
        include_local_policies = filter is None or EntityType.LocalManagedPolicy in filter
        include_aws_policies = filter is None or EntityType.AWSManagedPolicy in filter

        # Build role detail list
        role_detail_list = []
        if include_roles:
            for role_entity in store.ROLES.values():
                role_detail_list.append(self._build_role_detail(store, role_entity))

        # Build user detail list
        user_detail_list = []
        if include_users:
            for user_entity in store.USERS.values():
                user_detail_list.append(self._build_user_detail(store, user_entity))

        # Build group detail list
        group_detail_list = []
        if include_groups:
            for group_entity in store.GROUPS.values():
                group_detail_list.append(self._build_group_detail(store, group_entity))

        # Build policies list
        policies = []
        if include_local_policies:
            for policy_entity in store.MANAGED_POLICIES.values():
                policies.append(self._build_managed_policy_detail(policy_entity))

        if include_aws_policies:
            # Add AWS managed policies from cache
            for normalized_arn, policy_entity in self._aws_managed_policy_cache.items():
                policy_arn = normalized_arn.replace("arn:aws:", f"arn:{context.partition}:")
                aws_mp = store.AWS_MANAGED_POLICIES.get(policy_arn)
                attachment_count = aws_mp.attachment_count if aws_mp else 0

                # Build policy version list with documents
                policy_version_list = []
                for version_id, version in policy_entity.versions.items():
                    version_detail = PolicyVersion(version)
                    policy_version_list.append(version_detail)

                policy = policy_entity.policy
                detail = ManagedPolicyDetail(
                    PolicyName=policy.get("PolicyName"),
                    PolicyId=policy.get("PolicyId"),
                    Arn=policy_arn,
                    Path=policy.get("Path", "/"),
                    DefaultVersionId=policy.get("DefaultVersionId"),
                    AttachmentCount=attachment_count,
                    PermissionsBoundaryUsageCount=policy.get("PermissionsBoundaryUsageCount", 0),
                    IsAttachable=policy.get("IsAttachable", True),
                    CreateDate=policy.get("CreateDate"),
                    UpdateDate=policy.get("UpdateDate"),
                    PolicyVersionList=policy_version_list,
                )
                policies.append(detail)

        # TODO: Implement proper pagination
        return GetAccountAuthorizationDetailsResponse(
            UserDetailList=user_detail_list,
            GroupDetailList=group_detail_list,
            RoleDetailList=role_detail_list,
            Policies=policies,
            IsTruncated=False,
        )

    # ------------------------------ Credential Reports ------------------------------ #

    def _format_datetime_for_report(self, dt: datetime | None) -> str:
        """Format datetime for credential report CSV."""
        if dt is None:
            return "N/A"
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _generate_credential_report_csv(
        self, store: IamStore, account_id: str, partition: str
    ) -> bytes:
        """Generate the credential report CSV content."""
        output = io.StringIO()
        fieldnames = [
            "user",
            "arn",
            "user_creation_time",
            "password_enabled",
            "password_last_used",
            "password_last_changed",
            "password_next_rotation",
            "mfa_active",
            "access_key_1_active",
            "access_key_1_last_rotated",
            "access_key_1_last_used_date",
            "access_key_1_last_used_region",
            "access_key_1_last_used_service",
            "access_key_2_active",
            "access_key_2_last_rotated",
            "access_key_2_last_used_date",
            "access_key_2_last_used_region",
            "access_key_2_last_used_service",
            "cert_1_active",
            "cert_1_last_rotated",
            "cert_2_active",
            "cert_2_last_rotated",
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        # Add row for root account
        root_row = {
            "user": "<root_account>",
            "arn": f"arn:{partition}:iam::{account_id}:root",
            "user_creation_time": "N/A",
            "password_enabled": "not_supported",
            "password_last_used": "no_information",
            "password_last_changed": "not_supported",
            "password_next_rotation": "not_supported",
            "mfa_active": "false",
            "access_key_1_active": "false",
            "access_key_1_last_rotated": "N/A",
            "access_key_1_last_used_date": "N/A",
            "access_key_1_last_used_region": "N/A",
            "access_key_1_last_used_service": "N/A",
            "access_key_2_active": "false",
            "access_key_2_last_rotated": "N/A",
            "access_key_2_last_used_date": "N/A",
            "access_key_2_last_used_region": "N/A",
            "access_key_2_last_used_service": "N/A",
            "cert_1_active": "false",
            "cert_1_last_rotated": "N/A",
            "cert_2_active": "false",
            "cert_2_last_rotated": "N/A",
        }
        writer.writerow(root_row)

        # Add rows for each user
        with self._user_lock:
            for user_name, user_entity in store.USERS.items():
                user = user_entity.user

                # Password info
                has_password = user_entity.login_profile is not None
                password_enabled = "true" if has_password else "false"
                password_last_changed = "N/A"
                if has_password and user_entity.login_profile:
                    create_date = user_entity.login_profile.get("CreateDate")
                    if create_date:
                        password_last_changed = self._format_datetime_for_report(create_date)

                # MFA info
                mfa_active = "true" if user_entity.mfa_devices else "false"

                # Access keys - sorted by status (Active first), then by create date for stability
                # AWS credential reports show Active keys before Inactive ones
                access_keys = sorted(
                    user_entity.access_keys.values(),
                    key=lambda k: (
                        0 if k.access_key.get("Status") == "Active" else 1,
                        k.access_key.get("CreateDate") or datetime.min.replace(tzinfo=UTC),
                    ),
                )

                # Access key 1
                ak1_active = "false"
                ak1_rotated = "N/A"
                ak1_last_used_date = "N/A"
                ak1_last_used_region = "N/A"
                ak1_last_used_service = "N/A"
                if len(access_keys) >= 1:
                    ak1 = access_keys[0]
                    ak1_active = "true" if ak1.access_key.get("Status") == "Active" else "false"
                    ak1_rotated = self._format_datetime_for_report(ak1.access_key.get("CreateDate"))
                    if ak1.last_used:
                        last_used_date = ak1.last_used.get("LastUsedDate")
                        if last_used_date:
                            ak1_last_used_date = self._format_datetime_for_report(last_used_date)
                            ak1_last_used_region = ak1.last_used.get("Region", "N/A")
                            ak1_last_used_service = ak1.last_used.get("ServiceName", "N/A")

                # Access key 2
                ak2_active = "false"
                ak2_rotated = "N/A"
                ak2_last_used_date = "N/A"
                ak2_last_used_region = "N/A"
                ak2_last_used_service = "N/A"
                if len(access_keys) >= 2:
                    ak2 = access_keys[1]
                    ak2_active = "true" if ak2.access_key.get("Status") == "Active" else "false"
                    ak2_rotated = self._format_datetime_for_report(ak2.access_key.get("CreateDate"))
                    if ak2.last_used:
                        last_used_date = ak2.last_used.get("LastUsedDate")
                        if last_used_date:
                            ak2_last_used_date = self._format_datetime_for_report(last_used_date)
                            ak2_last_used_region = ak2.last_used.get("Region", "N/A")
                            ak2_last_used_service = ak2.last_used.get("ServiceName", "N/A")

                # Signing certificates
                certs = list(user_entity.signing_certificates.values())
                cert1_active = "false"
                cert1_rotated = "N/A"
                cert2_active = "false"
                cert2_rotated = "N/A"
                if len(certs) >= 1:
                    cert1_active = "true" if certs[0].get("Status") == "Active" else "false"
                    cert1_rotated = self._format_datetime_for_report(certs[0].get("UploadDate"))
                if len(certs) >= 2:
                    cert2_active = "true" if certs[1].get("Status") == "Active" else "false"
                    cert2_rotated = self._format_datetime_for_report(certs[1].get("UploadDate"))

                row = {
                    "user": user_name,
                    "arn": user.get("Arn"),
                    "user_creation_time": self._format_datetime_for_report(user.get("CreateDate")),
                    "password_enabled": password_enabled,
                    "password_last_used": "no_information",  # We don't track actual password usage
                    "password_last_changed": password_last_changed,
                    "password_next_rotation": "N/A",  # We don't enforce rotation
                    "mfa_active": mfa_active,
                    "access_key_1_active": ak1_active,
                    "access_key_1_last_rotated": ak1_rotated,
                    "access_key_1_last_used_date": ak1_last_used_date,
                    "access_key_1_last_used_region": ak1_last_used_region,
                    "access_key_1_last_used_service": ak1_last_used_service,
                    "access_key_2_active": ak2_active,
                    "access_key_2_last_rotated": ak2_rotated,
                    "access_key_2_last_used_date": ak2_last_used_date,
                    "access_key_2_last_used_region": ak2_last_used_region,
                    "access_key_2_last_used_service": ak2_last_used_service,
                    "cert_1_active": cert1_active,
                    "cert_1_last_rotated": cert1_rotated,
                    "cert_2_active": cert2_active,
                    "cert_2_last_rotated": cert2_rotated,
                }
            writer.writerow(row)

        return output.getvalue().encode("utf-8")

    def generate_credential_report(
        self, context: RequestContext, **kwargs
    ) -> GenerateCredentialReportResponse:
        """Generate a credential report for all users in the account."""
        store = self._get_store(context)

        # Check if a report already exists and is not older than 4 hours
        if store.CREDENTIAL_REPORT is not None and datetime.now(
            UTC
        ) - store.CREDENTIAL_REPORT.generated_at < timedelta(hours=4):
            return GenerateCredentialReportResponse(State=ReportStateType.COMPLETE)

        # Generate the report
        # TODO generate async
        csv_content = self._generate_credential_report_csv(
            store, context.account_id, context.partition
        )

        # Store the report
        store.CREDENTIAL_REPORT = CredentialReportEntity(
            content=csv_content,
            generated_at=datetime.now(UTC),
        )

        # Return STARTED on first generation
        return GenerateCredentialReportResponse(
            State=ReportStateType.STARTED,
            Description="No report exists. Starting a new report generation task",
        )

    def get_credential_report(
        self, context: RequestContext, **kwargs
    ) -> GetCredentialReportResponse:
        """Retrieve the generated credential report."""
        store = self._get_store(context)

        if store.CREDENTIAL_REPORT is None:
            raise CredentialReportNotPresentException()

        return GetCredentialReportResponse(
            Content=store.CREDENTIAL_REPORT.content,
            ReportFormat=ReportFormatType.text_csv,
            GeneratedTime=store.CREDENTIAL_REPORT.generated_at,
        )
