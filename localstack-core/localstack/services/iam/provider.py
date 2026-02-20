import base64
import inspect
import json
import logging
import random
import re
import string
import threading
import uuid
from datetime import UTC, datetime
from typing import Any, TypeVar
from urllib.parse import quote

from moto.iam.models import IAMBackend, iam_backends
from moto.iam.models import User as MotoUser

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.iam import (
    AttachedPermissionsBoundary,
    AttachedPolicy,
    CreatePolicyResponse,
    CreatePolicyVersionResponse,
    CreateRoleResponse,
    CreateServiceLinkedRoleResponse,
    CreateServiceSpecificCredentialResponse,
    CreateUserResponse,
    DeleteConflictException,
    DeleteServiceLinkedRoleResponse,
    DeletionTaskIdType,
    DeletionTaskStatusType,
    EntityAlreadyExistsException,
    GetPolicyResponse,
    GetPolicyVersionResponse,
    GetRolePolicyResponse,
    GetRoleResponse,
    GetServiceLinkedRoleDeletionStatusResponse,
    GetUserResponse,
    IamApi,
    InvalidInputException,
    LimitExceededException,
    ListAttachedRolePoliciesResponse,
    ListInstanceProfileTagsResponse,
    ListPoliciesResponse,
    ListPolicyTagsResponse,
    ListPolicyVersionsResponse,
    ListRolePoliciesResponse,
    ListRolesResponse,
    ListRoleTagsResponse,
    ListServiceSpecificCredentialsResponse,
    MalformedPolicyDocumentException,
    NoSuchEntityException,
    Policy,
    PolicyUsageType,
    PolicyVersion,
    ResetServiceSpecificCredentialResponse,
    Role,
    RoleLastUsed,
    ServiceSpecificCredential,
    ServiceSpecificCredentialMetadata,
    SimulatePolicyResponse,
    SimulatePrincipalPolicyRequest,
    Tag,
    UpdateRoleDescriptionResponse,
    UpdateRoleResponse,
    User,
    allUsers,
    arnType,
    booleanType,
    credentialAgeDays,
    customSuffixType,
    existingUserNameType,
    groupNameType,
    instanceProfileNameType,
    markerType,
    maxItemsType,
    pathPrefixType,
    pathType,
    policyDescriptionType,
    policyDocumentType,
    policyNameType,
    policyPathType,
    policyScopeType,
    policyVersionIdType,
    roleDescriptionType,
    roleMaxSessionDurationType,
    roleNameType,
    serviceName,
    serviceSpecificCredentialId,
    statusType,
    tagKeyListType,
    tagListType,
    userNameType,
)
from localstack.aws.connect import connect_to
from localstack.constants import INTERNAL_AWS_SECRET_ACCESS_KEY, TAG_KEY_CUSTOM_ID
from localstack.services.iam.iam_patches import apply_iam_patches
from localstack.services.iam.models import IamStore, ManagedPolicyEntity, RoleEntity, iam_stores
from localstack.services.iam.policy_validation import IAMPolicyDocumentValidator
from localstack.services.iam.resources.policy_simulator import (
    BasicIAMPolicySimulator,
    IAMPolicySimulator,
)
from localstack.services.iam.resources.service_linked_roles import SERVICE_LINKED_ROLES
from localstack.services.iam.utils import generate_iam_identifier
from localstack.services.moto import call_moto
from localstack.state import StateVisitor
from localstack.utils.aws.arns import get_partition
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

# Maximum versions per policy
MAX_POLICY_VERSIONS = 5

# Maximum tags per policy
MAX_POLICY_TAGS = 50

T = TypeVar("T")


class ValidationError(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("ValidationError", message, 400, True)


class ValidationListError(ValidationError):
    def __init__(self, validation_errors: list[str]):
        message = f"{len(validation_errors)} validation error{'s' if len(validation_errors) > 1 else ''} detected: {'; '.join(validation_errors)}"
        super().__init__(message)


def get_iam_backend(context: RequestContext) -> IAMBackend:
    return iam_backends[context.account_id][context.partition]


class IamProvider(IamApi):
    policy_simulator: IAMPolicySimulator
    _policy_lock: threading.Lock
    _role_lock: threading.Lock

    def __init__(self):
        apply_iam_patches()
        self.policy_simulator = BasicIAMPolicySimulator()
        self._policy_lock = threading.Lock()
        self._role_lock = threading.Lock()

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

        # Check if policy exists (for customer-managed policies)
        aws_managed_prefix = f"arn:{context.partition}:iam::aws:policy/"
        if not permissions_boundary.startswith(aws_managed_prefix):
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

            # TODO check if role is attached to instance profiles

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
        with self._policy_lock:
            policy_entity = self._get_policy_entity(store, policy_arn)

            # Return a copy of the policy with current tags (AWS returns empty list if no tags)
            policy = dict(policy_entity.policy)

        return GetPolicyResponse(Policy=policy)

    def delete_policy(self, context: RequestContext, policy_arn: arnType, **kwargs) -> None:
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

        def _map_to_list(policy: Policy) -> Policy:
            result = Policy(policy)
            if not result.get("Tags"):
                result.pop("Tags", None)
            return result

        paginated_list = PaginatedList(
            [_map_to_list(entity.policy) for entity in store.MANAGED_POLICIES.values()]
        )

        def _filter(policy: Policy):
            # Filter by scope - only "Local" customer-managed policies for now
            if scope == "AWS":
                return False

            # Filter by path prefix
            if path_prefix and not policy.get("Path", "/").startswith(path_prefix):
                return False

            # Filter by attached
            if only_attached and policy.get("AttachmentCount", 0) == 0:
                return False
            return True

        def _token_generator(policy: Policy):
            return policy.get("PolicyName")

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

    def update_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        new_path: pathType = None,
        new_group_name: groupNameType = None,
        **kwargs,
    ) -> None:
        new_group_name = new_group_name or group_name
        backend = get_iam_backend(context)
        group = backend.get_group(group_name)
        group.path = new_path
        group.name = new_group_name
        backend.groups[new_group_name] = backend.groups.pop(group_name)

    def list_instance_profile_tags(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListInstanceProfileTagsResponse:
        backend = get_iam_backend(context)
        profile = backend.get_instance_profile(instance_profile_name)
        response = ListInstanceProfileTagsResponse()
        response["Tags"] = profile.tags
        return response

    def tag_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        backend = get_iam_backend(context)
        profile = backend.get_instance_profile(instance_profile_name)
        new_keys = [tag["Key"] for tag in tags]
        updated_tags = [tag for tag in profile.tags if tag["Key"] not in new_keys]
        updated_tags.extend(tags)
        profile.tags = updated_tags

    def untag_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        backend = get_iam_backend(context)
        profile = backend.get_instance_profile(instance_profile_name)
        profile.tags = [tag for tag in profile.tags if tag["Key"] not in tag_keys]

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

    def put_user_permissions_boundary(
        self,
        context: RequestContext,
        user_name: userNameType,
        permissions_boundary: arnType,
        **kwargs,
    ) -> None:
        if user := get_iam_backend(context).users.get(user_name):
            user.permissions_boundary = permissions_boundary
        else:
            raise NoSuchEntityException()

    def delete_user_permissions_boundary(
        self, context: RequestContext, user_name: userNameType, **kwargs
    ) -> None:
        if user := get_iam_backend(context).users.get(user_name):
            if hasattr(user, "permissions_boundary"):
                delattr(user, "permissions_boundary")
        else:
            raise NoSuchEntityException()

    def create_user(
        self,
        context: RequestContext,
        user_name: userNameType,
        path: pathType = None,
        permissions_boundary: arnType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> CreateUserResponse:
        response = call_moto(context=context)
        user = get_iam_backend(context).get_user(user_name)
        if permissions_boundary:
            user.permissions_boundary = permissions_boundary
            response["User"]["PermissionsBoundary"] = AttachedPermissionsBoundary(
                PermissionsBoundaryArn=permissions_boundary,
                PermissionsBoundaryType="Policy",
            )
        return response

    def get_user(
        self, context: RequestContext, user_name: existingUserNameType = None, **kwargs
    ) -> GetUserResponse:
        response = call_moto(context=context)
        moto_user_name = response["User"]["UserName"]
        moto_user = get_iam_backend(context).users.get(moto_user_name)
        # if the user does not exist or is no user
        if not moto_user and not user_name:
            access_key_id = extract_access_key_id_from_auth_header(context.request.headers)
            sts_client = connect_to(
                region_name=context.region,
                aws_access_key_id=access_key_id,
                aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
            ).sts
            caller_identity = sts_client.get_caller_identity()
            caller_arn = caller_identity["Arn"]
            if caller_arn.endswith(":root"):
                return GetUserResponse(
                    User=User(
                        UserId=context.account_id,
                        Arn=caller_arn,
                        CreateDate=datetime.now(),
                        PasswordLastUsed=datetime.now(),
                    )
                )
            else:
                raise CommonServiceException(
                    "ValidationError",
                    "Must specify userName when calling with non-User credentials",
                )

        if hasattr(moto_user, "permissions_boundary") and moto_user.permissions_boundary:
            response["User"]["PermissionsBoundary"] = AttachedPermissionsBoundary(
                PermissionsBoundaryArn=moto_user.permissions_boundary,
                PermissionsBoundaryType="Policy",
            )

        return response

    def delete_user(
        self, context: RequestContext, user_name: existingUserNameType, **kwargs
    ) -> None:
        moto_user = get_iam_backend(context).users.get(user_name)
        if moto_user and moto_user.service_specific_credentials:
            LOG.info(
                "Cannot delete user '%s' because service specific credentials are still present.",
                user_name,
            )
            raise DeleteConflictException(
                "Cannot delete entity, must remove referenced objects first."
            )
        return call_moto(context=context)

    def attach_role_policy(
        self, context: RequestContext, role_name: roleNameType, policy_arn: arnType, **kwargs
    ) -> None:
        # Validate ARN format
        if not POLICY_ARN_REGEX.match(policy_arn):
            raise ValidationError(f"ARN {policy_arn} is not valid.")

        store = self._get_store(context)
        partition = get_partition(context.region)
        aws_managed_prefix = f"arn:{partition}:iam::aws:policy/"
        is_aws_managed = policy_arn.startswith(aws_managed_prefix)

        with self._role_lock, self._policy_lock:
            role_entity = self._get_role_entity(store, role_name)

            # Check if policy exists (for customer-managed policies only)
            if not is_aws_managed and policy_arn not in store.MANAGED_POLICIES:
                raise NoSuchEntityException(
                    f"Policy {policy_arn} does not exist or is not attachable."
                )

            # Add policy if not already attached (idempotent)
            if policy_arn not in role_entity.attached_policy_arns:
                role_entity.attached_policy_arns.append(policy_arn)

                # Update AttachmentCount for customer-managed policies
                if not is_aws_managed and policy_arn in store.MANAGED_POLICIES:
                    policy_entity = store.MANAGED_POLICIES[policy_arn]
                    policy_entity.policy["AttachmentCount"] += 1

    def detach_role_policy(
        self, context: RequestContext, role_name: roleNameType, policy_arn: arnType, **kwargs
    ) -> None:
        store = self._get_store(context)
        partition = get_partition(context.region)
        aws_managed_prefix = f"arn:{partition}:iam::aws:policy/"
        is_aws_managed = policy_arn.startswith(aws_managed_prefix)

        with self._role_lock, self._policy_lock:
            role_entity = self._get_role_entity(store, role_name)

            # Check if policy is attached
            if policy_arn not in role_entity.attached_policy_arns:
                raise NoSuchEntityException(f"Policy {policy_arn} was not found.")

            # Remove the policy
            role_entity.attached_policy_arns.remove(policy_arn)

            # Update AttachmentCount for customer-managed policies
            if not is_aws_managed and policy_arn in store.MANAGED_POLICIES:
                policy_entity = store.MANAGED_POLICIES[policy_arn]
                policy_entity.policy["AttachmentCount"] -= 1

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

    def attach_user_policy(
        self, context: RequestContext, user_name: userNameType, policy_arn: arnType, **kwargs
    ) -> None:
        if not POLICY_ARN_REGEX.match(policy_arn):
            raise ValidationError("Invalid ARN:  Could not be parsed!")
        return call_moto(context=context)

    # ------------------------------ Service specific credentials ------------------------------ #

    def _get_user_or_raise_error(self, user_name: str, context: RequestContext) -> MotoUser:
        """
        Return the moto user from the store, or raise the proper exception if no user can be found.

        :param user_name: Username to find
        :param context: Request context
        :return: A moto user object
        """
        moto_user = get_iam_backend(context).users.get(user_name)
        if not moto_user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")
        return moto_user

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
        moto_user = self._get_user_or_raise_error(user_name, context)
        self._validate_credential_id(credential_id)
        matching_credentials = [
            cred
            for cred in moto_user.service_specific_credentials
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
        moto_user = self._get_user_or_raise_error(user_name, context)
        self._validate_service_name(service_name)
        credential = self._new_service_specific_credential(user_name, service_name, context)
        moto_user.service_specific_credentials.append(credential)
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
        moto_user = self._get_user_or_raise_error(user_name, context)
        self._validate_service_name(service_name)
        result = [
            self.build_dict_with_only_defined_keys(creds, ServiceSpecificCredentialMetadata)
            for creds in moto_user.service_specific_credentials
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
        moto_user = self._get_user_or_raise_error(user_name, context)
        credentials = self._find_credential_in_user_by_id(
            user_name, service_specific_credential_id, context
        )
        try:
            moto_user.service_specific_credentials.remove(credentials)
        # just in case of race conditions
        except ValueError:
            raise NoSuchEntityException(
                f"No such credential {service_specific_credential_id} exists"
            )
