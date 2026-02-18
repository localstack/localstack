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

from moto.iam.models import (
    IAMBackend,
    filter_items_with_path_prefix,
    iam_backends,
)
from moto.iam.models import Role as MotoRole
from moto.iam.models import User as MotoUser
from moto.iam.utils import generate_access_key_id_from_account_id

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.iam import (
    AttachedPermissionsBoundary,
    CreatePolicyResponse,
    CreatePolicyVersionResponse,
    CreateRoleRequest,
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
    GetServiceLinkedRoleDeletionStatusResponse,
    GetUserResponse,
    IamApi,
    InvalidInputException,
    LimitExceededException,
    ListInstanceProfileTagsResponse,
    ListPoliciesResponse,
    ListPolicyTagsResponse,
    ListPolicyVersionsResponse,
    ListRolesResponse,
    ListServiceSpecificCredentialsResponse,
    MalformedPolicyDocumentException,
    NoSuchEntityException,
    Policy,
    PolicyUsageType,
    PolicyVersion,
    ResetServiceSpecificCredentialResponse,
    Role,
    ServiceSpecificCredential,
    ServiceSpecificCredentialMetadata,
    SimulatePolicyResponse,
    SimulatePrincipalPolicyRequest,
    Tag,
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
from localstack.services.iam.models import IamStore, ManagedPolicyEntity, iam_stores
from localstack.services.iam.policy_validation import IAMPolicyDocumentValidator
from localstack.services.iam.resources.policy_simulator import (
    BasicIAMPolicySimulator,
    IAMPolicySimulator,
)
from localstack.services.iam.resources.service_linked_roles import SERVICE_LINKED_ROLES
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

    def __init__(self):
        apply_iam_patches()
        self.policy_simulator = BasicIAMPolicySimulator()
        self._policy_lock = threading.Lock()

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(iam_backends)
        visitor.visit(iam_stores)

    @handler("CreateRole", expand=False)
    def create_role(
        self, context: RequestContext, request: CreateRoleRequest
    ) -> CreateRoleResponse:
        try:
            json.loads(request["AssumeRolePolicyDocument"])
        except json.JSONDecodeError:
            raise MalformedPolicyDocumentException("This policy contains invalid Json")
        result = call_moto(context)

        if not request.get("MaxSessionDuration") and result["Role"].get("MaxSessionDuration"):
            result["Role"].pop("MaxSessionDuration")

        if "RoleLastUsed" in result["Role"] and not result["Role"]["RoleLastUsed"]:
            # not part of the AWS response if it's empty
            # FIXME: RoleLastUsed did not seem well supported when this check was added
            result["Role"].pop("RoleLastUsed")

        return result

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

    def _validate_tags(self, tags: tagListType | None) -> None:
        """Validate tags according to AWS rules."""
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

            # Check for duplicate keys (case-sensitive)
            if key in seen_keys:
                raise InvalidInputException("Duplicate tag keys found.")
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
                Document=policy_document,
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
        store = self._get_store(context)
        with self._policy_lock:
            self._get_policy_entity(store, policy_arn)
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
                Document=policy_document,
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

    def detach_role_policy(
        self, context: RequestContext, role_name: roleNameType, policy_arn: arnType, **kwargs
    ) -> None:
        backend = get_iam_backend(context)
        try:
            role = backend.get_role(role_name)
            policy = role.managed_policies[policy_arn]
            policy.detach_from(role)
        except KeyError:
            raise NoSuchEntityException(f"Policy {policy_arn} was not found.")

    @staticmethod
    def moto_role_to_role_type(moto_role: MotoRole) -> Role:
        role = Role()
        role["Path"] = moto_role.path
        role["RoleName"] = moto_role.name
        role["RoleId"] = moto_role.id
        role["Arn"] = moto_role.arn
        role["CreateDate"] = moto_role.create_date
        if moto_role.assume_role_policy_document:
            role["AssumeRolePolicyDocument"] = moto_role.assume_role_policy_document
        if moto_role.description:
            role["Description"] = moto_role.description
        if moto_role.max_session_duration:
            role["MaxSessionDuration"] = moto_role.max_session_duration
        if moto_role.permissions_boundary:
            role["PermissionsBoundary"] = moto_role.permissions_boundary
        if moto_role.tags:
            role["Tags"] = moto_role.tags
        # role["RoleLastUsed"]: # TODO: add support
        return role

    def list_roles(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListRolesResponse:
        backend = get_iam_backend(context)
        moto_roles = backend.roles.values()
        if path_prefix:
            moto_roles = filter_items_with_path_prefix(path_prefix, moto_roles)
        moto_roles = sorted(moto_roles, key=lambda role: role.id)

        response_roles = []
        for moto_role in moto_roles:
            response_role = self.moto_role_to_role_type(moto_role)
            # Permission boundary and Tags should not be a part of the response
            response_role.pop("PermissionsBoundary", None)
            response_role.pop("Tags", None)
            response_roles.append(response_role)
            if path_prefix:  # TODO: this is consistent with the patch it migrates, but should add tests for this.
                response_role["AssumeRolePolicyDocument"] = quote(
                    json.dumps(moto_role.assume_role_policy_document or {})
                )

        return ListRolesResponse(Roles=response_roles, IsTruncated=False)

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
        backend = get_iam_backend(context)

        # check for role duplicates
        for role in backend.roles.values():
            if role.name == role_name:
                raise InvalidInputException(
                    f"Service role name {role_name} has been taken in this account, please try a different suffix."
                )

        role = backend.create_role(
            role_name=role_name,
            assume_role_policy_document=policy_doc,
            path=path,
            permissions_boundary="",
            description=description,
            tags={},
            max_session_duration=3600,
            linked_service=aws_service_name,
        )
        # attach policies
        for policy in attached_policies:
            try:
                backend.attach_role_policy(policy, role_name)
            except Exception as e:
                LOG.warning(
                    "Policy %s for service linked role %s does not exist: %s",
                    policy,
                    aws_service_name,
                    e,
                )

        res_role = self.moto_role_to_role_type(role)
        return CreateServiceLinkedRoleResponse(Role=res_role)

    def delete_service_linked_role(
        self, context: RequestContext, role_name: roleNameType, **kwargs
    ) -> DeleteServiceLinkedRoleResponse:
        backend = get_iam_backend(context)
        role = backend.get_role(role_name=role_name)
        role.managed_policies.clear()
        backend.delete_role(role_name)
        return DeleteServiceLinkedRoleResponse(
            DeletionTaskId=f"task{role.path}{role.name}/{uuid.uuid4()}"
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
        if not POLICY_ARN_REGEX.match(policy_arn):
            raise ValidationError("Invalid ARN:  Could not be parsed!")
        return call_moto(context=context)

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
        return generate_access_key_id_from_account_id(
            context.account_id, prefix="ACCA", total_length=21
        )

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
