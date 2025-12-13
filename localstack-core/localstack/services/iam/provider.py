import inspect
import json
import logging
import random
import re
import string
import uuid
from datetime import datetime
from typing import Any, TypeVar
from urllib.parse import quote

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.iam import (
    AccessKey,
    AccessKeyLastUsed as AccessKeyLastUsedType,
    AccessKeyMetadata,
    ActionNameListType,
    ActionNameType,
    accountAliasType,
    assignmentStatusType,
    attachedPoliciesListType,
    AttachedPermissionsBoundary,
    AttachedPolicy,
    authenticationCodeType,
    certificateBodyType,
    certificateChainType,
    certificateIdType,
    clientIDListType,
    clientIDType,
    ContextEntryListType,
    CreateAccessKeyResponse,
    CreateGroupResponse,
    CreateOpenIDConnectProviderResponse,
    CreatePolicyResponse,
    CreatePolicyVersionResponse,
    CreateLoginProfileResponse,
    CreateRoleRequest,
    CreateRoleResponse,
    CreateSAMLProviderResponse,
    CreateServiceLinkedRoleResponse,
    CreateServiceSpecificCredentialResponse,
    CreateUserResponse,
    CreateVirtualMFADeviceResponse,
    CredentialReportNotPresentException,
    CredentialReportNotReadyException,
    DeleteConflictException,
    DeleteServiceLinkedRoleResponse,
    DeletionTaskIdType,
    DeletionTaskStatusType,
    EntityAlreadyExistsException,
    EntityTemporarilyUnmodifiableException,
    EntityType,
    EvaluationResult,
    GenerateCredentialReportResponse,
    GetAccessKeyLastUsedResponse,
    GetAccountAuthorizationDetailsResponse,
    GetAccountPasswordPolicyResponse,
    GetAccountSummaryResponse,
    GetCredentialReportResponse,
    GetGroupPolicyResponse,
    GetGroupResponse,
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
    InvalidInputException,
    LimitExceededException,
    ListAccessKeysResponse,
    ListAccountAliasesResponse,
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
    InstanceProfile as InstanceProfileType,
    CreateInstanceProfileResponse,
    GetInstanceProfileResponse,
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
    ListUserTagsResponse,
    ListUsersResponse,
    ListVirtualMFADevicesResponse,
    MalformedPolicyDocumentException,
    maxPasswordAgeType,
    MFADevice,
    minimumPasswordLengthType,
    NoSuchEntityException,
    OpenIDConnectProviderListEntry,
    PasswordPolicy as PasswordPolicyType,
    passwordReusePreventionType,
    Policy,
    PolicyDetail,
    PolicyEvaluationDecisionType,
    PolicyGroup,
    PolicyRole,
    PolicyUser,
    PolicyVersion as PolicyVersionType,
    privateKeyType,
    publicKeyMaterialType,
    ReportFormatType,
    ReportStateType,
    ResetServiceSpecificCredentialResponse,
    ResourceHandlingOptionType,
    ResourceNameListType,
    ResourceNameType,
    Role,
    RoleDetail,
    RoleLastUsed as RoleLastUsedType,
    SAMLMetadataDocumentType,
    SAMLProviderListEntry,
    SAMLProviderNameType,
    ServerCertificate,
    ServerCertificateMetadata,
    serverCertificateNameType,
    ServiceSpecificCredential,
    ServiceSpecificCredentialMetadata,
    SimulatePolicyResponse,
    SimulationPolicyListType,
    SSHPublicKey,
    SSHPublicKeyMetadata,
    SigningCertificate as SigningCertificateType,
    summaryKeyType,
    thumbprintListType,
    thumbprintType,
    UpdateRoleResponse,
    UpdateSAMLProviderResponse,
    UploadServerCertificateResponse,
    UploadSigningCertificateResponse,
    UploadSSHPublicKeyResponse,
    User,
    UserDetail,
    VirtualMFADevice as VirtualMFADeviceType,
    accessKeyIdType,
    allUsers,
    arnType,
    booleanType,
    booleanObjectType,
    credentialAgeDays,
    customSuffixType,
    encodingType,
    existingUserNameType,
    groupNameType,
    instanceProfileNameType,
    markerType,
    maxItemsType,
    OpenIDConnectProviderUrlType,
    passwordType,
    pathPrefixType,
    pathType,
    policyDocumentType,
    policyNameType,
    policyScopeType,
    policyVersionIdType,
    publicKeyIdType,
    roleDescriptionType,
    roleMaxSessionDurationType,
    roleNameType,
    serialNumberType,
    serviceName,
    serviceSpecificCredentialId,
    statusType,
    tagKeyListType,
    tagListType,
    userNameType,
    virtualMFADeviceName,
)
from localstack.aws.connect import connect_to
from localstack.constants import INTERNAL_AWS_SECRET_ACCESS_KEY
from localstack.services.iam.models import (
    AccessKey as AccessKeyModel,
    AccessKeyLastUsed as AccessKeyLastUsedModel,
    Group as GroupModel,
    IamStore,
    InstanceProfile as InstanceProfileModel,
    LoginProfile as LoginProfileModel,
    ManagedPolicy as ManagedPolicyModel,
    OIDCProvider as OIDCProviderModel,
    PasswordPolicy as PasswordPolicyModel,
    PermissionsBoundary,
    PolicyVersion,
    Role as RoleModel,
    RoleLastUsed,
    SAMLProvider as SAMLProviderModel,
    ServerCertificate as ServerCertificateModel,
    SigningCertificate as SigningCertificateModel,
    SSHPublicKey as SSHPublicKeyModel,
    User as UserModel,
    VirtualMFADevice as VirtualMFADeviceModel,
    build_group_arn,
    build_instance_profile_arn,
    build_mfa_device_arn,
    build_oidc_provider_arn,
    build_policy_arn,
    build_role_arn,
    build_saml_provider_arn,
    build_server_certificate_arn,
    build_user_arn,
    generate_access_key_id,
    generate_certificate_id,
    generate_group_id,
    generate_instance_profile_id,
    generate_policy_id,
    generate_role_id,
    generate_secret_access_key,
    generate_server_certificate_id,
    generate_ssh_public_key_id,
    generate_user_id,
    iam_stores,
)
from localstack.services.iam.pagination import filter_by_path_prefix, paginate_list
from localstack.services.iam.resources.service_linked_roles import SERVICE_LINKED_ROLES
from localstack.services.iam.validation import (
    check_access_keys_limit,
    check_attached_policies_limit,
    check_group_limit,
    check_policy_limit,
    check_policy_versions_limit,
    check_role_limit,
    check_user_limit,
    entity_exists_error,
    entity_not_found_error,
    tags_to_list,
    validate_group_name,
    validate_inline_policy_name,
    validate_instance_profile_name,
    validate_path,
    validate_policy_arn,
    validate_policy_document,
    validate_policy_name,
    validate_role_name,
    validate_tags,
    validate_trust_policy_document,
    validate_user_name,
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.state import StateVisitor
from localstack.utils.aws.request_context import extract_access_key_id_from_auth_header

LOG = logging.getLogger(__name__)

SERVICE_LINKED_ROLE_PATH_PREFIX = "/aws-service-role"

POLICY_ARN_REGEX = re.compile(r"arn:[^:]+:iam::(?:\d{12}|aws):policy/.*")

CREDENTIAL_ID_REGEX = re.compile(r"^\w+$")

T = TypeVar("T")


class ValidationError(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("ValidationError", message, 400, True)


class ValidationListError(ValidationError):
    def __init__(self, validation_errors: list[str]):
        message = f"{len(validation_errors)} validation error{'s' if len(validation_errors) > 1 else ''} detected: {'; '.join(validation_errors)}"
        super().__init__(message)


def get_policies_from_principal_native(store: IamStore, principal_arn: str) -> list[str]:
    """
    Extract all policies associated with a principal (role, group, or user).

    Native implementation replacing moto.
    Returns a list of policy document strings.
    """
    policies = []

    if ":role" in principal_arn:
        role_name = principal_arn.split("/")[-1]
        role = store.roles.get(role_name)
        if role:
            # Add assume role policy
            policies.append(role.assume_role_policy_document)
            # Add inline policies
            policies.extend(role.inline_policies.values())
            # Add attached managed policies
            for policy_arn in role.attached_policies:
                policy = store.policies.get(policy_arn.split("/")[-1])
                if policy:
                    default_version = policy.get_default_version()
                    if default_version:
                        policies.append(default_version.document)

    if ":group" in principal_arn:
        group_name = principal_arn.split("/")[-1]
        group = store.groups.get(group_name)
        if group:
            # Add inline policies
            policies.extend(group.inline_policies.values())
            # Add attached managed policies
            for policy_arn in group.attached_policies:
                policy = store.policies.get(policy_arn.split("/")[-1])
                if policy:
                    default_version = policy.get_default_version()
                    if default_version:
                        policies.append(default_version.document)

    if ":user" in principal_arn:
        user_name = principal_arn.split("/")[-1]
        user = store.users.get(user_name)
        if user:
            # Add inline policies
            policies.extend(user.inline_policies.values())
            # Add attached managed policies
            for policy_arn in user.attached_policies:
                policy = store.policies.get(policy_arn.split("/")[-1])
                if policy:
                    default_version = policy.get_default_version()
                    if default_version:
                        policies.append(default_version.document)

    return policies


class IamProvider(IamApi, ServiceLifecycleHook):
    """
    Native IAM provider implementation.

    This provider replaces the moto-based implementation with a fully native
    LocalStack implementation using the AccountRegionBundle pattern.
    """

    # =========================================================================
    # Store Access and Lifecycle Methods
    # =========================================================================

    def get_store(self, account_id: str, region: str) -> IamStore:
        """
        Get the IAM store for the given account and region.

        Note: IAM is a global service, so all IAM resources are shared across
        regions within an account. The region parameter is still required for
        the store access pattern but doesn't affect data isolation.

        :param account_id: AWS account ID
        :param region: AWS region name
        :return: IamStore instance for the account
        """
        return iam_stores[account_id][region]

    def accept_state_visitor(self, visitor: StateVisitor):
        """
        Accept a state visitor for persistence operations.

        This method is called by LocalStack's persistence layer to save/load
        the IAM service state.
        """
        visitor.visit(iam_stores)

    def on_after_state_load(self):
        """
        Hook called after state has been loaded from persistence.

        Rebuilds any runtime indexes or caches that are not persisted.
        """
        # Rebuild indexes in all stores
        for account_id, region_bundle in iam_stores.items():
            for region_name, store in region_bundle.items():
                store.rebuild_indexes()

    # =========================================================================
    # Role CRUD Operations (Native Implementation)
    # =========================================================================

    def _role_model_to_api(self, role: RoleModel, include_trust_policy: bool = True) -> Role:
        """
        Convert internal Role model to AWS API Role type.

        :param role: Internal Role model
        :param include_trust_policy: Whether to include AssumeRolePolicyDocument
        :return: AWS API Role dict
        """
        api_role = Role(
            Path=role.path,
            RoleName=role.role_name,
            RoleId=role.role_id,
            Arn=role.arn,
            CreateDate=role.create_date,
        )
        if include_trust_policy and role.assume_role_policy_document:
            api_role["AssumeRolePolicyDocument"] = role.assume_role_policy_document
        if role.description:
            api_role["Description"] = role.description
        if role.max_session_duration != 3600:  # Only include if non-default
            api_role["MaxSessionDuration"] = role.max_session_duration
        if role.permission_boundary:
            api_role["PermissionsBoundary"] = AttachedPermissionsBoundary(
                PermissionsBoundaryArn=role.permission_boundary.permissions_boundary_arn,
                PermissionsBoundaryType=role.permission_boundary.permissions_boundary_type,
            )
        if role.tags:
            api_role["Tags"] = tags_to_list(role.tags)
        if role.last_used and role.last_used.last_used_date:
            api_role["RoleLastUsed"] = RoleLastUsedType(
                LastUsedDate=role.last_used.last_used_date,
                Region=role.last_used.region,
            )
        return api_role

    @handler("CreateRole", expand=False)
    def create_role(
        self, context: RequestContext, request: CreateRoleRequest
    ) -> CreateRoleResponse:
        """
        Create a new IAM role.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        role_name = request["RoleName"]
        assume_role_policy_document = request["AssumeRolePolicyDocument"]
        path = request.get("Path")
        description = request.get("Description")
        max_session_duration = request.get("MaxSessionDuration", 3600)
        permissions_boundary = request.get("PermissionsBoundary")
        tags = request.get("Tags")

        # Validate inputs
        validate_role_name(role_name)
        normalized_path = validate_path(path, "role")

        # Validate trust policy document
        validate_trust_policy_document(assume_role_policy_document)

        # Check if role already exists
        if role_name in store.roles:
            raise EntityAlreadyExistsException(
                f"Role with name {role_name} already exists."
            )

        # Check role limit
        check_role_limit(len(store.roles))

        # Validate permission boundary if provided
        permission_boundary_model = None
        if permissions_boundary:
            validate_policy_arn(permissions_boundary)
            permission_boundary_model = PermissionsBoundary(
                permissions_boundary_arn=permissions_boundary,
                permissions_boundary_type="Policy",
            )

        # Validate tags
        validated_tags = validate_tags(tags) if tags else {}

        # Validate max session duration (3600 - 43200 seconds)
        if max_session_duration < 3600 or max_session_duration > 43200:
            raise InvalidInputException(
                f"MaxSessionDuration must be between 3600 and 43200 seconds."
            )

        # Generate role ID and ARN
        role_id = generate_role_id()
        role_arn = build_role_arn(context.account_id, normalized_path, role_name)

        # Create role model
        role = RoleModel(
            role_name=role_name,
            role_id=role_id,
            arn=role_arn,
            assume_role_policy_document=assume_role_policy_document,
            path=normalized_path,
            create_date=datetime.utcnow(),
            description=description,
            max_session_duration=max_session_duration,
            permission_boundary=permission_boundary_model,
            tags=validated_tags,
        )

        # Store the role
        store.roles[role_name] = role

        # Build response (don't include MaxSessionDuration if default)
        api_role = self._role_model_to_api(role)
        if max_session_duration == 3600:
            api_role.pop("MaxSessionDuration", None)

        return CreateRoleResponse(Role=api_role)

    def get_role(
        self, context: RequestContext, role_name: roleNameType, **kwargs
    ) -> GetRoleResponse:
        """
        Get information about an IAM role.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        role = store.get_role(role_name)
        if not role:
            raise NoSuchEntityException(
                f"The role with name {role_name} cannot be found."
            )

        return GetRoleResponse(Role=self._role_model_to_api(role))

    @staticmethod
    def build_evaluation_result(
        action_name: ActionNameType, resource_name: ResourceNameType, policy_statements: list[dict]
    ) -> EvaluationResult:
        eval_res = EvaluationResult()
        eval_res["EvalActionName"] = action_name
        eval_res["EvalResourceName"] = resource_name
        eval_res["EvalDecision"] = PolicyEvaluationDecisionType.explicitDeny
        for statement in policy_statements:
            # TODO Implement evaluation logic here
            if (
                action_name in statement["Action"]
                and resource_name in statement["Resource"]
                and statement["Effect"] == "Allow"
            ):
                eval_res["EvalDecision"] = PolicyEvaluationDecisionType.allowed
                eval_res["MatchedStatements"] = []  # TODO: add support for statement compilation.
        return eval_res

    def simulate_principal_policy(
        self,
        context: RequestContext,
        policy_source_arn: arnType,
        action_names: ActionNameListType,
        policy_input_list: SimulationPolicyListType = None,
        permissions_boundary_policy_input_list: SimulationPolicyListType = None,
        resource_arns: ResourceNameListType = None,
        resource_policy: policyDocumentType = None,
        resource_owner: ResourceNameType = None,
        caller_arn: ResourceNameType = None,
        context_entries: ContextEntryListType = None,
        resource_handling_option: ResourceHandlingOptionType = None,
        max_items: maxItemsType = None,
        marker: markerType = None,
        **kwargs,
    ) -> SimulatePolicyResponse:
        """
        Simulate the effects of IAM policies attached to a principal.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        policies = get_policies_from_principal_native(store, policy_source_arn)

        def _get_statements_from_policy_list(policies: list[str]):
            statements = []
            for policy_str in policies:
                policy_dict = json.loads(policy_str)
                if isinstance(policy_dict["Statement"], list):
                    statements.extend(policy_dict["Statement"])
                else:
                    statements.append(policy_dict["Statement"])
            return statements

        policy_statements = _get_statements_from_policy_list(policies)

        evaluations = [
            self.build_evaluation_result(action_name, resource_arn, policy_statements)
            for action_name in action_names
            for resource_arn in resource_arns
        ]

        response = SimulatePolicyResponse()
        response["IsTruncated"] = False
        response["EvaluationResults"] = evaluations
        return response

    # =========================================================================
    # Policy CRUD Operations (Native Implementation)
    # =========================================================================

    def _policy_model_to_api(self, policy: ManagedPolicyModel) -> Policy:
        """
        Convert internal ManagedPolicy model to AWS API Policy type.

        :param policy: Internal ManagedPolicy model
        :return: AWS API Policy dict
        """
        api_policy = Policy(
            PolicyName=policy.policy_name,
            PolicyId=policy.policy_id,
            Arn=policy.arn,
            Path=policy.path,
            DefaultVersionId=policy.default_version_id,
            AttachmentCount=policy.attachment_count,
            IsAttachable=policy.is_attachable,
            CreateDate=policy.create_date,
            UpdateDate=policy.update_date,
        )
        if policy.description:
            api_policy["Description"] = policy.description
        if policy.tags:
            api_policy["Tags"] = tags_to_list(policy.tags)
        return api_policy

    def _policy_version_to_api(self, version: PolicyVersion) -> PolicyVersionType:
        """
        Convert internal PolicyVersion model to AWS API PolicyVersion type.

        :param version: Internal PolicyVersion model
        :return: AWS API PolicyVersion dict
        """
        return PolicyVersionType(
            VersionId=version.version_id,
            Document=version.document,
            IsDefaultVersion=version.is_default_version,
            CreateDate=version.create_date,
        )

    def create_policy(
        self,
        context: RequestContext,
        policy_name: policyNameType,
        policy_document: policyDocumentType,
        path: pathType = None,
        description: policyDocumentType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> CreatePolicyResponse:
        """
        Create a new managed IAM policy.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Validate inputs
        validate_policy_name(policy_name)
        normalized_path = validate_path(path, "policy")

        # Validate policy document
        validate_policy_document(policy_document)

        # Build ARN and check if policy already exists
        policy_arn = build_policy_arn(context.account_id, normalized_path, policy_name)
        if policy_arn in store.policies:
            raise EntityAlreadyExistsException(
                f"A policy called {policy_name} already exists. Duplicate names are not allowed."
            )

        # Check policy limit
        check_policy_limit(len(store.policies))

        # Validate tags
        validated_tags = validate_tags(tags) if tags else {}

        # Generate policy ID
        policy_id = generate_policy_id()

        # Create first version
        first_version = PolicyVersion(
            version_id="v1",
            document=policy_document,
            is_default_version=True,
            create_date=datetime.utcnow(),
        )

        # Create policy model
        policy = ManagedPolicyModel(
            policy_name=policy_name,
            policy_id=policy_id,
            arn=policy_arn,
            path=normalized_path,
            create_date=datetime.utcnow(),
            update_date=datetime.utcnow(),
            description=description,
            default_version_id="v1",
            is_attachable=True,
            tags=validated_tags,
            versions=[first_version],
        )

        # Store the policy
        store.policies[policy_arn] = policy

        return CreatePolicyResponse(Policy=self._policy_model_to_api(policy))

    def get_policy(
        self, context: RequestContext, policy_arn: arnType, **kwargs
    ) -> GetPolicyResponse:
        """
        Get information about a managed policy.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        policy = store.get_policy_by_arn(policy_arn)
        if not policy:
            raise NoSuchEntityException(
                f"Policy {policy_arn} does not exist or is not attachable."
            )

        return GetPolicyResponse(Policy=self._policy_model_to_api(policy))

    def list_policies(
        self,
        context: RequestContext,
        scope: policyScopeType = None,
        only_attached: bool = None,
        path_prefix: pathPrefixType = None,
        policy_usage_filter: str = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListPoliciesResponse:
        """
        List managed policies with optional filtering and pagination.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Collect all policies (customer + AWS managed if scope allows)
        all_policies = []

        # Add customer managed policies
        if not scope or scope in ("All", "Local"):
            all_policies.extend(store.policies.values())

        # Add AWS managed policies
        if not scope or scope in ("All", "AWS"):
            all_policies.extend(store.AWS_MANAGED_POLICIES.values())

        # Filter by path prefix
        if path_prefix:
            all_policies = filter_by_path_prefix(
                all_policies, path_prefix, get_path=lambda p: p.path
            )

        # Filter by attachment status
        if only_attached:
            all_policies = [p for p in all_policies if p.attachment_count > 0]

        # Sort by ARN
        all_policies = sorted(all_policies, key=lambda p: p.arn)

        # Paginate results
        paginated = paginate_list(
            items=all_policies,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda p: p.arn,
        )

        # Convert to API format
        api_policies = [self._policy_model_to_api(p) for p in paginated.items]

        response = ListPoliciesResponse(
            Policies=api_policies,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    def delete_policy(self, context: RequestContext, policy_arn: arnType, **kwargs) -> None:
        """
        Delete a managed policy.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Check if it's an AWS managed policy (cannot be deleted)
        if policy_arn.startswith("arn:aws:iam::aws:policy/"):
            raise NoSuchEntityException(
                f"Policy {policy_arn} cannot be deleted."
            )

        policy = store.policies.get(policy_arn)
        if not policy:
            raise NoSuchEntityException(f"Policy {policy_arn} does not exist.")

        # Check if policy is attached
        if policy.attachment_count > 0:
            raise DeleteConflictException(
                "Cannot delete a policy attached to entities."
            )

        # Check if policy has non-default versions
        if len(policy.versions) > 1:
            raise DeleteConflictException(
                "Cannot delete a policy with non-default versions. Delete all non-default versions first."
            )

        # Delete the policy
        del store.policies[policy_arn]

    def create_policy_version(
        self,
        context: RequestContext,
        policy_arn: arnType,
        policy_document: policyDocumentType,
        set_as_default: bool = None,
        **kwargs,
    ) -> CreatePolicyVersionResponse:
        """
        Create a new version of a managed policy.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        policy = store.policies.get(policy_arn)
        if not policy:
            raise NoSuchEntityException(
                f"Policy {policy_arn} does not exist or is not attachable."
            )

        # Check version limit (max 5)
        check_policy_versions_limit(len(policy.versions))

        # Validate policy document
        validate_policy_document(policy_document)

        # Determine new version ID
        max_version = max(int(v.version_id[1:]) for v in policy.versions)
        new_version_id = f"v{max_version + 1}"

        # Create new version
        new_version = PolicyVersion(
            version_id=new_version_id,
            document=policy_document,
            is_default_version=bool(set_as_default),
            create_date=datetime.utcnow(),
        )

        # If setting as default, unset current default
        if set_as_default:
            for version in policy.versions:
                version.is_default_version = False
            policy.default_version_id = new_version_id

        # Add version
        policy.versions.append(new_version)
        policy.update_date = datetime.utcnow()

        return CreatePolicyVersionResponse(
            PolicyVersion=self._policy_version_to_api(new_version)
        )

    def get_policy_version(
        self,
        context: RequestContext,
        policy_arn: arnType,
        version_id: policyVersionIdType,
        **kwargs,
    ) -> GetPolicyVersionResponse:
        """
        Get a specific version of a managed policy.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        policy = store.get_policy_by_arn(policy_arn)
        if not policy:
            raise NoSuchEntityException(
                f"Policy {policy_arn} does not exist or is not attachable."
            )

        version = policy.get_version(version_id)
        if not version:
            raise NoSuchEntityException(
                f"Policy version {version_id} does not exist."
            )

        return GetPolicyVersionResponse(
            PolicyVersion=self._policy_version_to_api(version)
        )

    def list_policy_versions(
        self,
        context: RequestContext,
        policy_arn: arnType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListPolicyVersionsResponse:
        """
        List all versions of a managed policy.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        policy = store.get_policy_by_arn(policy_arn)
        if not policy:
            raise NoSuchEntityException(
                f"Policy {policy_arn} does not exist or is not attachable."
            )

        # Sort versions by version ID
        sorted_versions = sorted(policy.versions, key=lambda v: int(v.version_id[1:]))

        # Paginate results
        paginated = paginate_list(
            items=sorted_versions,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda v: v.version_id,
        )

        # Convert to API format (without Document for list operations)
        api_versions = []
        for v in paginated.items:
            api_version = PolicyVersionType(
                VersionId=v.version_id,
                IsDefaultVersion=v.is_default_version,
                CreateDate=v.create_date,
            )
            api_versions.append(api_version)

        response = ListPolicyVersionsResponse(
            Versions=api_versions,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    def delete_policy_version(
        self,
        context: RequestContext,
        policy_arn: arnType,
        version_id: policyVersionIdType,
        **kwargs,
    ) -> None:
        """
        Delete a specific version of a managed policy.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        policy = store.policies.get(policy_arn)
        if not policy:
            raise NoSuchEntityException(
                f"Policy {policy_arn} does not exist or is not attachable."
            )

        version = policy.get_version(version_id)
        if not version:
            raise NoSuchEntityException(
                f"Policy version {version_id} does not exist."
            )

        # Cannot delete the default version
        if version.is_default_version:
            raise DeleteConflictException(
                "Cannot delete the default version of a policy."
            )

        # Remove the version
        policy.versions = [v for v in policy.versions if v.version_id != version_id]
        policy.update_date = datetime.utcnow()

    def set_default_policy_version(
        self,
        context: RequestContext,
        policy_arn: arnType,
        version_id: policyVersionIdType,
        **kwargs,
    ) -> None:
        """
        Set the default version of a managed policy.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        policy = store.policies.get(policy_arn)
        if not policy:
            raise NoSuchEntityException(
                f"Policy {policy_arn} does not exist or is not attachable."
            )

        version = policy.get_version(version_id)
        if not version:
            raise NoSuchEntityException(
                f"Policy version {version_id} does not exist."
            )

        # Unset current default
        for v in policy.versions:
            v.is_default_version = False

        # Set new default
        version.is_default_version = True
        policy.default_version_id = version_id
        policy.update_date = datetime.utcnow()

    def list_roles(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListRolesResponse:
        """
        List IAM roles with optional path prefix filtering and pagination.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Get all roles sorted by name
        all_roles = sorted(store.roles.values(), key=lambda r: r.role_name)

        # Filter by path prefix if specified
        if path_prefix:
            all_roles = filter_by_path_prefix(
                all_roles, path_prefix, get_path=lambda r: r.path
            )

        # Paginate results
        paginated = paginate_list(
            items=all_roles,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda r: r.role_name,
        )

        # Convert to API format (without PermissionsBoundary and Tags per AWS behavior)
        response_roles = []
        for role in paginated.items:
            api_role = self._role_model_to_api(role)
            # Per AWS behavior, list_roles doesn't include these
            api_role.pop("PermissionsBoundary", None)
            api_role.pop("Tags", None)
            # URL-encode the trust policy for list operations
            if role.assume_role_policy_document:
                api_role["AssumeRolePolicyDocument"] = quote(role.assume_role_policy_document)
            response_roles.append(api_role)

        response = ListRolesResponse(
            Roles=response_roles,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    def update_assume_role_policy(
        self,
        context: RequestContext,
        role_name: roleNameType,
        policy_document: policyDocumentType,
        **kwargs,
    ) -> None:
        """
        Update the trust policy (assume role policy) for an IAM role.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        role = store.get_role(role_name)
        if not role:
            raise NoSuchEntityException(
                f"The role with name {role_name} cannot be found."
            )

        # Validate trust policy document
        validate_trust_policy_document(policy_document)

        # Update the trust policy
        role.assume_role_policy_document = policy_document

    def delete_role(
        self, context: RequestContext, role_name: roleNameType, **kwargs
    ) -> None:
        """
        Delete an IAM role.

        Checks for dependencies before deletion.
        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        role = store.get_role(role_name)
        if not role:
            raise NoSuchEntityException(
                f"The role with name {role_name} cannot be found."
            )

        # Check for dependencies
        if role.instance_profiles:
            raise DeleteConflictException(
                "Cannot delete entity, must remove role from instance profile(s) first."
            )
        if role.attached_policies:
            raise DeleteConflictException(
                "Cannot delete entity, must detach all policies first."
            )
        if role.inline_policies:
            raise DeleteConflictException(
                "Cannot delete entity, must delete inline policies first."
            )

        # Delete the role
        del store.roles[role_name]

    def update_role(
        self,
        context: RequestContext,
        role_name: roleNameType,
        description: roleDescriptionType = None,
        max_session_duration: roleMaxSessionDurationType = None,
        **kwargs,
    ) -> UpdateRoleResponse:
        """
        Update an IAM role's description and/or max session duration.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        role = store.get_role(role_name)
        if not role:
            raise NoSuchEntityException(f"Role {role_name} not found")

        if description is not None:
            role.description = description

        if max_session_duration is not None:
            if max_session_duration < 3600 or max_session_duration > 43200:
                raise InvalidInputException(
                    "MaxSessionDuration must be between 3600 and 43200 seconds"
                )
            role.max_session_duration = max_session_duration

        return UpdateRoleResponse()

    def tag_role(
        self,
        context: RequestContext,
        role_name: roleNameType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        """
        Add tags to an IAM role.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        role = store.get_role(role_name)
        if not role:
            raise NoSuchEntityException(f"Role {role_name} not found")

        # Add/update tags
        for tag in tags:
            role.tags[tag["Key"]] = tag["Value"]

    def untag_role(
        self,
        context: RequestContext,
        role_name: roleNameType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        """
        Remove tags from an IAM role.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        role = store.get_role(role_name)
        if not role:
            raise NoSuchEntityException(f"Role {role_name} not found")

        # Remove tags
        for key in tag_keys:
            role.tags.pop(key, None)

    def list_role_tags(
        self,
        context: RequestContext,
        role_name: roleNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListRoleTagsResponse:
        """
        List tags attached to an IAM role.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        role = store.get_role(role_name)
        if not role:
            raise NoSuchEntityException(f"Role {role_name} not found")

        # Convert tags dict to list format
        tags = [{"Key": k, "Value": v} for k, v in role.tags.items()]

        return ListRoleTagsResponse(Tags=tags, IsTruncated=False)

    # =========================================================================
    # Group CRUD Operations (Native Implementation)
    # =========================================================================

    def _group_model_to_api(self, group: GroupModel) -> Group:
        """
        Convert internal Group model to AWS API Group type.

        :param group: Internal Group model
        :return: AWS API Group dict
        """
        return Group(
            Path=group.path,
            GroupName=group.group_name,
            GroupId=group.group_id,
            Arn=group.arn,
            CreateDate=group.create_date,
        )

    def create_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        path: pathType = None,
        **kwargs,
    ) -> CreateGroupResponse:
        """
        Create a new IAM group.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Validate inputs
        validate_group_name(group_name)
        normalized_path = validate_path(path, "group")

        # Check if group already exists
        if group_name in store.groups:
            raise EntityAlreadyExistsException(
                f"Group with name {group_name} already exists."
            )

        # Check group limit
        check_group_limit(len(store.groups))

        # Generate group ID and ARN
        group_id = generate_group_id()
        group_arn = build_group_arn(context.account_id, normalized_path, group_name)

        # Create group model
        group = GroupModel(
            group_name=group_name,
            group_id=group_id,
            arn=group_arn,
            path=normalized_path,
            create_date=datetime.utcnow(),
        )

        # Store the group
        store.groups[group_name] = group

        return CreateGroupResponse(Group=self._group_model_to_api(group))

    def get_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> GetGroupResponse:
        """
        Get information about an IAM group, including its members.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        group = store.get_group(group_name)
        if not group:
            raise NoSuchEntityException(
                f"The group with name {group_name} cannot be found."
            )

        # Get group members
        members = []
        for user_name in group.users:
            user = store.get_user(user_name)
            if user:
                members.append(self._user_model_to_api(user))

        # Paginate members if needed
        paginated = paginate_list(
            items=members,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda u: u["UserName"],
        )

        response = GetGroupResponse(
            Group=self._group_model_to_api(group),
            Users=paginated.items,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    def list_groups(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListGroupsResponse:
        """
        List IAM groups with optional path prefix filtering and pagination.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Get all groups sorted by name
        all_groups = sorted(store.groups.values(), key=lambda g: g.group_name)

        # Filter by path prefix if specified
        if path_prefix:
            all_groups = filter_by_path_prefix(
                all_groups, path_prefix, get_path=lambda g: g.path
            )

        # Paginate results
        paginated = paginate_list(
            items=all_groups,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda g: g.group_name,
        )

        # Convert to API format
        api_groups = [self._group_model_to_api(group) for group in paginated.items]

        response = ListGroupsResponse(
            Groups=api_groups,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    def update_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        new_path: pathType = None,
        new_group_name: groupNameType = None,
        **kwargs,
    ) -> None:
        """
        Update an IAM group's name and/or path.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        group = store.get_group(group_name)
        if not group:
            raise NoSuchEntityException(
                f"The group with name {group_name} cannot be found."
            )

        # Check if renaming to a name that already exists
        if new_group_name and new_group_name != group_name:
            validate_group_name(new_group_name)
            if new_group_name in store.groups:
                raise EntityAlreadyExistsException(
                    f"Group with name {new_group_name} already exists."
                )

        # Validate new path if provided
        if new_path:
            normalized_path = validate_path(new_path, "group")
            group.path = normalized_path

        # Update group name if provided
        if new_group_name and new_group_name != group_name:
            # Remove from old key
            del store.groups[group_name]
            # Update group properties
            group.group_name = new_group_name
            group.arn = build_group_arn(context.account_id, group.path, new_group_name)
            # Store under new key
            store.groups[new_group_name] = group

            # Update group reference in all member users
            for user_name in group.users:
                user = store.get_user(user_name)
                if user and group_name in user.groups:
                    user.groups.remove(group_name)
                    user.groups.append(new_group_name)
        elif new_path:
            # Just update ARN for path change
            group.arn = build_group_arn(context.account_id, group.path, group.group_name)

        return None

    def delete_group(
        self, context: RequestContext, group_name: groupNameType, **kwargs
    ) -> None:
        """
        Delete an IAM group.

        Checks for dependencies before deletion.
        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        group = store.get_group(group_name)
        if not group:
            raise NoSuchEntityException(
                f"The group with name {group_name} cannot be found."
            )

        # Check for dependencies
        if group.users:
            raise DeleteConflictException(
                "Cannot delete entity, must remove users from group first."
            )
        if group.attached_policies:
            raise DeleteConflictException(
                "Cannot delete entity, must detach all policies first."
            )
        if group.inline_policies:
            raise DeleteConflictException(
                "Cannot delete entity, must delete inline policies first."
            )

        # Delete the group
        del store.groups[group_name]

    # =========================================================================
    # Group Membership Operations (Native Implementation)
    # =========================================================================

    def add_user_to_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        user_name: existingUserNameType,
        **kwargs,
    ) -> None:
        """
        Add a user to a group.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify group exists
        group = store.get_group(group_name)
        if not group:
            raise NoSuchEntityException(
                f"The group with name {group_name} cannot be found."
            )

        # Verify user exists
        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Check if user is already in group
        if user_name in group.users:
            return  # Already a member, no-op

        # Add user to group
        group.users.append(user_name)
        user.groups.append(group_name)

    def remove_user_from_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        user_name: existingUserNameType,
        **kwargs,
    ) -> None:
        """
        Remove a user from a group.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify group exists
        group = store.get_group(group_name)
        if not group:
            raise NoSuchEntityException(
                f"The group with name {group_name} cannot be found."
            )

        # Verify user exists
        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Check if user is in group
        if user_name not in group.users:
            raise NoSuchEntityException(
                f"The user with name {user_name} is not in group {group_name}."
            )

        # Remove user from group
        group.users.remove(user_name)
        if group_name in user.groups:
            user.groups.remove(group_name)

    def list_groups_for_user(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListGroupsForUserResponse:
        """
        List all groups that a user belongs to.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify user exists
        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Get all groups the user belongs to
        user_groups = []
        for group_name in sorted(user.groups):
            group = store.get_group(group_name)
            if group:
                user_groups.append(self._group_model_to_api(group))

        # Paginate results
        paginated = paginate_list(
            items=user_groups,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda g: g["GroupName"],
        )

        response = ListGroupsForUserResponse(
            Groups=paginated.items,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    def list_instance_profile_tags(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListInstanceProfileTagsResponse:
        """
        List tags for an instance profile.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)
        profile = store.instance_profiles.get(instance_profile_name)
        if not profile:
            raise NoSuchEntityException(
                f"Instance profile {instance_profile_name} cannot be found."
            )

        # Convert tags to API format
        tags_list = tags_to_list(profile.tags)

        # Paginate
        paginated = paginate_list(
            items=tags_list,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda t: t["Key"],
        )

        response = ListInstanceProfileTagsResponse(
            Tags=paginated.items,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker
        return response

    def tag_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        """
        Add or update tags on an instance profile.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)
        profile = store.instance_profiles.get(instance_profile_name)
        if not profile:
            raise NoSuchEntityException(
                f"Instance profile {instance_profile_name} cannot be found."
            )

        # Update tags
        new_tags = validate_tags(tags) if tags else {}
        profile.tags.update(new_tags)

    def untag_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        """
        Remove tags from an instance profile.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)
        profile = store.instance_profiles.get(instance_profile_name)
        if not profile:
            raise NoSuchEntityException(
                f"Instance profile {instance_profile_name} cannot be found."
            )

        # Remove specified tags
        for key in tag_keys:
            profile.tags.pop(key, None)

    def create_service_linked_role(
        self,
        context: RequestContext,
        aws_service_name: groupNameType,
        description: roleDescriptionType = None,
        custom_suffix: customSuffixType = None,
        **kwargs,
    ) -> CreateServiceLinkedRoleResponse:
        """
        Create a service-linked role for an AWS service.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

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

        # Check for role duplicates
        if role_name in store.roles:
            raise InvalidInputException(
                f"Service role name {role_name} has been taken in this account, please try a different suffix."
            )

        # Generate ID and ARN
        role_id = generate_role_id()
        arn = build_role_arn(context.account_id, path, role_name)

        # Create the role
        role = RoleModel(
            role_name=role_name,
            role_id=role_id,
            arn=arn,
            path=path,
            assume_role_policy_document=policy_doc,
            description=description or "",
            max_session_duration=3600,
        )

        store.roles[role_name] = role

        # Attach policies
        for policy_arn in attached_policies:
            try:
                if policy_arn not in role.attached_policies:
                    role.attached_policies.append(policy_arn)
            except Exception as e:
                LOG.warning(
                    "Policy %s for service linked role %s does not exist: %s",
                    policy_arn,
                    aws_service_name,
                    e,
                )

        # Convert to API response type
        role_response = Role(
            Path=role.path,
            RoleName=role.role_name,
            RoleId=role.role_id,
            Arn=role.arn,
            CreateDate=role.create_date,
            AssumeRolePolicyDocument=quote(role.assume_role_policy_document),
        )
        if role.description:
            role_response["Description"] = role.description
        if role.max_session_duration:
            role_response["MaxSessionDuration"] = role.max_session_duration

        return CreateServiceLinkedRoleResponse(Role=role_response)

    def delete_service_linked_role(
        self, context: RequestContext, role_name: roleNameType, **kwargs
    ) -> DeleteServiceLinkedRoleResponse:
        """
        Delete a service-linked role.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        role = store.roles.get(role_name)
        if not role:
            raise NoSuchEntityException(f"Role {role_name} cannot be found.")

        # Clear attached policies
        role.attached_policies.clear()

        # Generate deletion task ID
        deletion_task_id = f"task{role.path}{role.role_name}/{uuid.uuid4()}"

        # Delete the role
        del store.roles[role_name]

        return DeleteServiceLinkedRoleResponse(DeletionTaskId=deletion_task_id)

    def get_service_linked_role_deletion_status(
        self, context: RequestContext, deletion_task_id: DeletionTaskIdType, **kwargs
    ) -> GetServiceLinkedRoleDeletionStatusResponse:
        """
        Get the status of a service-linked role deletion.

        Native implementation - always returns SUCCEEDED.
        """
        # TODO: Track actual deletion tasks if needed
        return GetServiceLinkedRoleDeletionStatusResponse(Status=DeletionTaskStatusType.SUCCEEDED)

    def put_user_permissions_boundary(
        self,
        context: RequestContext,
        user_name: userNameType,
        permissions_boundary: arnType,
        **kwargs,
    ) -> None:
        """
        Set a permissions boundary for a user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)
        user = store.users.get(user_name)
        if not user:
            raise NoSuchEntityException(f"User {user_name} cannot be found.")

        user.permissions_boundary = PermissionsBoundary(
            permissions_boundary_type="Policy",
            permissions_boundary_arn=permissions_boundary,
        )

    def delete_user_permissions_boundary(
        self, context: RequestContext, user_name: userNameType, **kwargs
    ) -> None:
        """
        Delete a user's permissions boundary.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)
        user = store.users.get(user_name)
        if not user:
            raise NoSuchEntityException(f"User {user_name} cannot be found.")

        user.permissions_boundary = None

    # =========================================================================
    # User CRUD Operations (Native Implementation)
    # =========================================================================

    def _user_model_to_api(self, user: UserModel) -> User:
        """
        Convert internal User model to AWS API User type.

        :param user: Internal User model
        :return: AWS API User dict
        """
        api_user = User(
            Path=user.path,
            UserName=user.user_name,
            UserId=user.user_id,
            Arn=user.arn,
            CreateDate=user.create_date,
        )
        if user.password_last_used:
            api_user["PasswordLastUsed"] = user.password_last_used
        if user.permission_boundary:
            api_user["PermissionsBoundary"] = AttachedPermissionsBoundary(
                PermissionsBoundaryArn=user.permission_boundary.permissions_boundary_arn,
                PermissionsBoundaryType=user.permission_boundary.permissions_boundary_type,
            )
        if user.tags:
            api_user["Tags"] = tags_to_list(user.tags)
        return api_user

    def create_user(
        self,
        context: RequestContext,
        user_name: userNameType,
        path: pathType = None,
        permissions_boundary: arnType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> CreateUserResponse:
        """
        Create a new IAM user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Validate inputs
        validate_user_name(user_name)
        normalized_path = validate_path(path, "user")

        # Check if user already exists
        if user_name in store.users:
            raise EntityAlreadyExistsException(
                f"User with name {user_name} already exists."
            )

        # Check user limit
        check_user_limit(len(store.users))

        # Validate permission boundary if provided
        permission_boundary_model = None
        if permissions_boundary:
            validate_policy_arn(permissions_boundary)
            permission_boundary_model = PermissionsBoundary(
                permissions_boundary_arn=permissions_boundary,
                permissions_boundary_type="Policy",
            )

        # Validate tags
        validated_tags = validate_tags(tags) if tags else {}

        # Generate user ID and ARN
        user_id = generate_user_id()
        user_arn = build_user_arn(context.account_id, normalized_path, user_name)

        # Create user model
        user = UserModel(
            user_name=user_name,
            user_id=user_id,
            arn=user_arn,
            path=normalized_path,
            create_date=datetime.utcnow(),
            permission_boundary=permission_boundary_model,
            tags=validated_tags,
        )

        # Store the user
        store.users[user_name] = user

        return CreateUserResponse(User=self._user_model_to_api(user))

    def get_user(
        self, context: RequestContext, user_name: existingUserNameType = None, **kwargs
    ) -> GetUserResponse:
        """
        Get information about an IAM user.

        If no username is provided, returns info about the calling user (or root).
        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # If no user_name provided, get info about the caller
        if not user_name:
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

        # Look up user by name
        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        return GetUserResponse(User=self._user_model_to_api(user))

    def list_users(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListUsersResponse:
        """
        List IAM users with optional path prefix filtering and pagination.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Get all users sorted by name
        all_users = sorted(store.users.values(), key=lambda u: u.user_name)

        # Filter by path prefix if specified
        if path_prefix:
            all_users = filter_by_path_prefix(
                all_users, path_prefix, get_path=lambda u: u.path
            )

        # Paginate results
        paginated = paginate_list(
            items=all_users,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda u: u.user_name,
        )

        # Convert to API format
        api_users = [self._user_model_to_api(user) for user in paginated.items]

        response = ListUsersResponse(
            Users=api_users,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    def update_user(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        new_path: pathType = None,
        new_user_name: userNameType = None,
        **kwargs,
    ) -> None:
        """
        Update an IAM user's name and/or path.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Get existing user
        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Check if renaming to a name that already exists
        if new_user_name and new_user_name != user_name:
            validate_user_name(new_user_name)
            if new_user_name in store.users:
                raise EntityAlreadyExistsException(
                    f"User with name {new_user_name} already exists."
                )

        # Validate new path if provided
        if new_path:
            normalized_path = validate_path(new_path, "user")
            user.path = normalized_path

        # Update username if provided
        if new_user_name and new_user_name != user_name:
            # Remove from old key
            del store.users[user_name]
            # Update user properties
            user.user_name = new_user_name
            user.arn = build_user_arn(context.account_id, user.path, new_user_name)
            # Store under new key
            store.users[new_user_name] = user
        elif new_path:
            # Just update ARN for path change
            user.arn = build_user_arn(context.account_id, user.path, user.user_name)

        return None

    def delete_user(
        self, context: RequestContext, user_name: existingUserNameType, **kwargs
    ) -> None:
        """
        Delete an IAM user.

        Checks for dependencies before deletion.
        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Get existing user
        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Check for dependencies that must be removed first
        if user.access_keys:
            raise DeleteConflictException(
                "Cannot delete entity, must delete access keys first."
            )
        if user.mfa_devices:
            raise DeleteConflictException(
                "Cannot delete entity, must deactivate MFA devices first."
            )
        if user.service_specific_credentials:
            LOG.info(
                "Cannot delete user '%s' because service specific credentials are still present.",
                user_name,
            )
            raise DeleteConflictException(
                "Cannot delete entity, must remove referenced objects first."
            )
        if user.groups:
            raise DeleteConflictException(
                "Cannot delete entity, must remove user from all groups first."
            )
        if user.attached_policies:
            raise DeleteConflictException(
                "Cannot delete entity, must detach all policies first."
            )
        if user.inline_policies:
            raise DeleteConflictException(
                "Cannot delete entity, must delete inline policies first."
            )
        if user.login_profile:
            raise DeleteConflictException(
                "Cannot delete entity, must delete login profile first."
            )
        if user.ssh_public_keys:
            raise DeleteConflictException(
                "Cannot delete entity, must delete SSH public keys first."
            )
        if user.signing_certificates:
            raise DeleteConflictException(
                "Cannot delete entity, must delete signing certificates first."
            )

        # Delete the user
        del store.users[user_name]

    def tag_user(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        """
        Add tags to an IAM user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Add/update tags
        for tag in tags:
            user.tags[tag["Key"]] = tag["Value"]

    def untag_user(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        """
        Remove tags from an IAM user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Remove tags
        for key in tag_keys:
            user.tags.pop(key, None)

    def list_user_tags(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListUserTagsResponse:
        """
        List tags attached to an IAM user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Convert tags dict to list format
        tags = [{"Key": k, "Value": v} for k, v in user.tags.items()]

        return ListUserTagsResponse(Tags=tags, IsTruncated=False)

    # =========================================================================
    # Login Profile Operations (Native Implementation)
    # =========================================================================

    def create_login_profile(
        self,
        context: RequestContext,
        user_name: userNameType,
        password: passwordType,
        password_reset_required: booleanType = None,
        **kwargs,
    ) -> CreateLoginProfileResponse:
        """
        Create a login profile (console password) for an IAM user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        if user.login_profile:
            raise EntityAlreadyExistsException(
                f"Login Profile for User {user_name} already exists."
            )

        # Create login profile
        login_profile = LoginProfileModel(
            user_name=user_name,
            create_date=datetime.utcnow(),
            password_reset_required=password_reset_required or False,
        )
        user.login_profile = login_profile

        return CreateLoginProfileResponse(
            LoginProfile={
                "UserName": user_name,
                "CreateDate": login_profile.create_date,
                "PasswordResetRequired": login_profile.password_reset_required,
            }
        )

    def get_login_profile(
        self,
        context: RequestContext,
        user_name: userNameType,
        **kwargs,
    ) -> GetLoginProfileResponse:
        """
        Get the login profile for an IAM user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        if not user.login_profile:
            raise NoSuchEntityException(
                f"Login Profile for User {user_name} cannot be found."
            )

        return GetLoginProfileResponse(
            LoginProfile={
                "UserName": user_name,
                "CreateDate": user.login_profile.create_date,
                "PasswordResetRequired": user.login_profile.password_reset_required,
            }
        )

    def update_login_profile(
        self,
        context: RequestContext,
        user_name: userNameType,
        password: passwordType = None,
        password_reset_required: booleanType = None,
        **kwargs,
    ) -> None:
        """
        Update the login profile for an IAM user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        if not user.login_profile:
            raise NoSuchEntityException(
                f"Login Profile for User {user_name} cannot be found."
            )

        if password_reset_required is not None:
            user.login_profile.password_reset_required = password_reset_required

    def delete_login_profile(
        self,
        context: RequestContext,
        user_name: userNameType,
        **kwargs,
    ) -> None:
        """
        Delete the login profile for an IAM user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        if not user.login_profile:
            raise NoSuchEntityException(
                f"Login Profile for User {user_name} cannot be found."
            )

        user.login_profile = None

    # =========================================================================
    # Access Key Operations (Native Implementation)
    # =========================================================================

    def create_access_key(
        self,
        context: RequestContext,
        user_name: existingUserNameType = None,
        **kwargs,
    ) -> CreateAccessKeyResponse:
        """
        Create a new access key for a user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # If no user_name provided, use the calling user
        if not user_name:
            # For now, require user_name (root user key creation handled separately)
            raise InvalidInputException("UserName is required.")

        # Verify user exists
        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Check access key limit (max 2 per user)
        check_access_keys_limit(len(user.access_keys))

        # Generate access key credentials
        access_key_id = generate_access_key_id()
        secret_access_key = generate_secret_access_key()

        # Create access key model
        access_key = AccessKeyModel(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            user_name=user_name,
            status="Active",
            create_date=datetime.utcnow(),
        )

        # Store access key
        store.access_keys[access_key_id] = access_key
        user.access_keys.append(access_key_id)

        # Update index
        if user_name not in store._access_key_by_user:
            store._access_key_by_user[user_name] = []
        store._access_key_by_user[user_name].append(access_key_id)

        # Initialize last used tracking
        store.access_key_last_used[access_key_id] = AccessKeyLastUsedModel(
            access_key_id=access_key_id
        )

        return CreateAccessKeyResponse(
            AccessKey=AccessKey(
                UserName=user_name,
                AccessKeyId=access_key_id,
                Status="Active",
                SecretAccessKey=secret_access_key,
                CreateDate=access_key.create_date,
            )
        )

    def list_access_keys(
        self,
        context: RequestContext,
        user_name: existingUserNameType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListAccessKeysResponse:
        """
        List access keys for a user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # If no user_name provided, use the calling user
        if not user_name:
            raise InvalidInputException("UserName is required.")

        # Verify user exists
        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Get access keys for user
        access_keys = []
        for key_id in user.access_keys:
            key = store.get_access_key(key_id)
            if key:
                access_keys.append(AccessKeyMetadata(
                    UserName=key.user_name,
                    AccessKeyId=key.access_key_id,
                    Status=key.status,
                    CreateDate=key.create_date,
                ))

        # Paginate results
        paginated = paginate_list(
            items=access_keys,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda k: k["AccessKeyId"],
        )

        response = ListAccessKeysResponse(
            AccessKeyMetadata=paginated.items,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    def update_access_key(
        self,
        context: RequestContext,
        access_key_id: accessKeyIdType,
        status: statusType,
        user_name: existingUserNameType = None,
        **kwargs,
    ) -> None:
        """
        Update the status of an access key (Active/Inactive).

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Get access key
        access_key = store.get_access_key(access_key_id)
        if not access_key:
            raise NoSuchEntityException(
                f"The Access Key with id {access_key_id} cannot be found."
            )

        # Verify user_name matches if provided
        if user_name and access_key.user_name != user_name:
            raise NoSuchEntityException(
                f"The Access Key with id {access_key_id} cannot be found."
            )

        # Update status
        if status not in ("Active", "Inactive"):
            raise InvalidInputException("Status must be 'Active' or 'Inactive'.")

        access_key.status = status

    def delete_access_key(
        self,
        context: RequestContext,
        access_key_id: accessKeyIdType,
        user_name: existingUserNameType = None,
        **kwargs,
    ) -> None:
        """
        Delete an access key.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Get access key
        access_key = store.get_access_key(access_key_id)
        if not access_key:
            raise NoSuchEntityException(
                f"The Access Key with id {access_key_id} cannot be found."
            )

        # Verify user_name matches if provided
        if user_name and access_key.user_name != user_name:
            raise NoSuchEntityException(
                f"The Access Key with id {access_key_id} cannot be found."
            )

        # Get user and remove key reference
        user = store.get_user(access_key.user_name)
        if user and access_key_id in user.access_keys:
            user.access_keys.remove(access_key_id)

        # Remove from index
        if access_key.user_name in store._access_key_by_user:
            if access_key_id in store._access_key_by_user[access_key.user_name]:
                store._access_key_by_user[access_key.user_name].remove(access_key_id)

        # Delete access key and last used tracking
        del store.access_keys[access_key_id]
        store.access_key_last_used.pop(access_key_id, None)

    def get_access_key_last_used(
        self,
        context: RequestContext,
        access_key_id: accessKeyIdType,
        **kwargs,
    ) -> GetAccessKeyLastUsedResponse:
        """
        Get information about when an access key was last used.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Get access key
        access_key = store.get_access_key(access_key_id)
        if not access_key:
            raise NoSuchEntityException(
                f"The Access Key with id {access_key_id} cannot be found."
            )

        # Get last used info
        last_used = store.access_key_last_used.get(access_key_id)

        response = GetAccessKeyLastUsedResponse(
            UserName=access_key.user_name,
        )

        if last_used and last_used.last_used_date:
            response["AccessKeyLastUsed"] = AccessKeyLastUsedType(
                LastUsedDate=last_used.last_used_date,
                ServiceName=last_used.service_name or "N/A",
                Region=last_used.region or "N/A",
            )
        else:
            # Key has never been used
            response["AccessKeyLastUsed"] = AccessKeyLastUsedType(
                ServiceName="N/A",
                Region="N/A",
            )

        return response

    # =========================================================================
    # Policy Attachment Operations - User (Native Implementation)
    # =========================================================================

    def put_user_policy(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        policy_name: policyNameType,
        policy_document: policyDocumentType,
        **kwargs,
    ) -> None:
        """
        Add or update an inline policy for a user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify user exists
        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Validate policy name and document
        validate_inline_policy_name(policy_name)
        validate_policy_document(policy_document)

        # Add/update inline policy
        user.inline_policies[policy_name] = policy_document

    def get_user_policy(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> GetUserPolicyResponse:
        """
        Get an inline policy for a user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify user exists
        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Get inline policy
        policy_document = user.inline_policies.get(policy_name)
        if not policy_document:
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
        """
        List inline policies for a user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify user exists
        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Get policy names
        policy_names = sorted(user.inline_policies.keys())

        # Paginate results
        paginated = paginate_list(
            items=policy_names,
            marker=marker,
            max_items=max_items,
        )

        response = ListUserPoliciesResponse(
            PolicyNames=paginated.items,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    def delete_user_policy(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> None:
        """
        Delete an inline policy from a user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify user exists
        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Delete inline policy
        if policy_name not in user.inline_policies:
            raise NoSuchEntityException(
                f"The user policy with name {policy_name} cannot be found."
            )

        del user.inline_policies[policy_name]

    def attach_user_policy(
        self, context: RequestContext, user_name: userNameType, policy_arn: arnType, **kwargs
    ) -> None:
        """
        Attach a managed policy to a user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Validate policy ARN
        validate_policy_arn(policy_arn)

        # Verify user exists
        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Verify policy exists
        policy = store.get_policy_by_arn(policy_arn)
        if not policy:
            raise NoSuchEntityException(
                f"Policy {policy_arn} does not exist or is not attachable."
            )

        # Check if already attached
        if policy_arn in user.attached_policies:
            return  # No-op if already attached

        # Check attached policies limit
        check_attached_policies_limit(len(user.attached_policies), "user")

        # Attach policy
        user.attached_policies.append(policy_arn)
        policy.attachment_count += 1

    def detach_user_policy(
        self, context: RequestContext, user_name: userNameType, policy_arn: arnType, **kwargs
    ) -> None:
        """
        Detach a managed policy from a user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify user exists
        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Check if attached
        if policy_arn not in user.attached_policies:
            raise NoSuchEntityException(
                f"Policy {policy_arn} is not attached to user {user_name}."
            )

        # Detach policy
        user.attached_policies.remove(policy_arn)

        # Update policy attachment count
        policy = store.get_policy_by_arn(policy_arn)
        if policy and policy.attachment_count > 0:
            policy.attachment_count -= 1

    def list_attached_user_policies(
        self,
        context: RequestContext,
        user_name: userNameType,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListAttachedUserPoliciesResponse:
        """
        List managed policies attached to a user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify user exists
        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(
                f"The user with name {user_name} cannot be found."
            )

        # Get attached policies
        attached_policies = []
        for policy_arn in user.attached_policies:
            policy = store.get_policy_by_arn(policy_arn)
            if policy:
                # Filter by path prefix if specified
                if path_prefix and not policy.path.startswith(path_prefix):
                    continue
                attached_policies.append(AttachedPolicy(
                    PolicyName=policy.policy_name,
                    PolicyArn=policy.arn,
                ))

        # Sort by policy name
        attached_policies.sort(key=lambda p: p["PolicyName"])

        # Paginate results
        paginated = paginate_list(
            items=attached_policies,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda p: p["PolicyArn"],
        )

        response = ListAttachedUserPoliciesResponse(
            AttachedPolicies=paginated.items,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    # =========================================================================
    # Policy Attachment Operations - Role (Native Implementation)
    # =========================================================================

    def put_role_policy(
        self,
        context: RequestContext,
        role_name: roleNameType,
        policy_name: policyNameType,
        policy_document: policyDocumentType,
        **kwargs,
    ) -> None:
        """
        Add or update an inline policy for a role.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify role exists
        role = store.get_role(role_name)
        if not role:
            raise NoSuchEntityException(
                f"The role with name {role_name} cannot be found."
            )

        # Validate policy name and document
        validate_inline_policy_name(policy_name)
        validate_policy_document(policy_document)

        # Add/update inline policy
        role.inline_policies[policy_name] = policy_document

    def get_role_policy(
        self,
        context: RequestContext,
        role_name: roleNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> GetRolePolicyResponse:
        """
        Get an inline policy for a role.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify role exists
        role = store.get_role(role_name)
        if not role:
            raise NoSuchEntityException(
                f"The role with name {role_name} cannot be found."
            )

        # Get inline policy
        policy_document = role.inline_policies.get(policy_name)
        if not policy_document:
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
        """
        List inline policies for a role.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify role exists
        role = store.get_role(role_name)
        if not role:
            raise NoSuchEntityException(
                f"The role with name {role_name} cannot be found."
            )

        # Get policy names
        policy_names = sorted(role.inline_policies.keys())

        # Paginate results
        paginated = paginate_list(
            items=policy_names,
            marker=marker,
            max_items=max_items,
        )

        response = ListRolePoliciesResponse(
            PolicyNames=paginated.items,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    def delete_role_policy(
        self,
        context: RequestContext,
        role_name: roleNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> None:
        """
        Delete an inline policy from a role.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify role exists
        role = store.get_role(role_name)
        if not role:
            raise NoSuchEntityException(
                f"The role with name {role_name} cannot be found."
            )

        # Delete inline policy
        if policy_name not in role.inline_policies:
            raise NoSuchEntityException(
                f"The role policy with name {policy_name} cannot be found."
            )

        del role.inline_policies[policy_name]

    def attach_role_policy(
        self, context: RequestContext, role_name: roleNameType, policy_arn: arnType, **kwargs
    ) -> None:
        """
        Attach a managed policy to a role.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Validate policy ARN
        validate_policy_arn(policy_arn)

        # Verify role exists
        role = store.get_role(role_name)
        if not role:
            raise NoSuchEntityException(
                f"The role with name {role_name} cannot be found."
            )

        # Verify policy exists
        policy = store.get_policy_by_arn(policy_arn)
        if not policy:
            raise NoSuchEntityException(
                f"Policy {policy_arn} does not exist or is not attachable."
            )

        # Check if already attached
        if policy_arn in role.attached_policies:
            return  # No-op if already attached

        # Check attached policies limit
        check_attached_policies_limit(len(role.attached_policies), "role")

        # Attach policy
        role.attached_policies.append(policy_arn)
        policy.attachment_count += 1

    def detach_role_policy(
        self, context: RequestContext, role_name: roleNameType, policy_arn: arnType, **kwargs
    ) -> None:
        """
        Detach a managed policy from a role.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify role exists
        role = store.get_role(role_name)
        if not role:
            raise NoSuchEntityException(
                f"The role with name {role_name} cannot be found."
            )

        # Check if attached
        if policy_arn not in role.attached_policies:
            raise NoSuchEntityException(
                f"Policy {policy_arn} is not attached to role {role_name}."
            )

        # Detach policy
        role.attached_policies.remove(policy_arn)

        # Update policy attachment count
        policy = store.get_policy_by_arn(policy_arn)
        if policy and policy.attachment_count > 0:
            policy.attachment_count -= 1

    def list_attached_role_policies(
        self,
        context: RequestContext,
        role_name: roleNameType,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListAttachedRolePoliciesResponse:
        """
        List managed policies attached to a role.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify role exists
        role = store.get_role(role_name)
        if not role:
            raise NoSuchEntityException(
                f"The role with name {role_name} cannot be found."
            )

        # Get attached policies
        attached_policies = []
        for policy_arn in role.attached_policies:
            policy = store.get_policy_by_arn(policy_arn)
            if policy:
                # Filter by path prefix if specified
                if path_prefix and not policy.path.startswith(path_prefix):
                    continue
                attached_policies.append(AttachedPolicy(
                    PolicyName=policy.policy_name,
                    PolicyArn=policy.arn,
                ))

        # Sort by policy name
        attached_policies.sort(key=lambda p: p["PolicyName"])

        # Paginate results
        paginated = paginate_list(
            items=attached_policies,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda p: p["PolicyArn"],
        )

        response = ListAttachedRolePoliciesResponse(
            AttachedPolicies=paginated.items,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    # =========================================================================
    # Policy Attachment Operations - Group (Native Implementation)
    # =========================================================================

    def put_group_policy(
        self,
        context: RequestContext,
        group_name: groupNameType,
        policy_name: policyNameType,
        policy_document: policyDocumentType,
        **kwargs,
    ) -> None:
        """
        Add or update an inline policy for a group.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify group exists
        group = store.get_group(group_name)
        if not group:
            raise NoSuchEntityException(
                f"The group with name {group_name} cannot be found."
            )

        # Validate policy name and document
        validate_inline_policy_name(policy_name)
        validate_policy_document(policy_document)

        # Add/update inline policy
        group.inline_policies[policy_name] = policy_document

    def get_group_policy(
        self,
        context: RequestContext,
        group_name: groupNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> GetGroupPolicyResponse:
        """
        Get an inline policy for a group.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify group exists
        group = store.get_group(group_name)
        if not group:
            raise NoSuchEntityException(
                f"The group with name {group_name} cannot be found."
            )

        # Get inline policy
        policy_document = group.inline_policies.get(policy_name)
        if not policy_document:
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
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListGroupPoliciesResponse:
        """
        List inline policies for a group.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify group exists
        group = store.get_group(group_name)
        if not group:
            raise NoSuchEntityException(
                f"The group with name {group_name} cannot be found."
            )

        # Get policy names
        policy_names = sorted(group.inline_policies.keys())

        # Paginate results
        paginated = paginate_list(
            items=policy_names,
            marker=marker,
            max_items=max_items,
        )

        response = ListGroupPoliciesResponse(
            PolicyNames=paginated.items,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    def delete_group_policy(
        self,
        context: RequestContext,
        group_name: groupNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> None:
        """
        Delete an inline policy from a group.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify group exists
        group = store.get_group(group_name)
        if not group:
            raise NoSuchEntityException(
                f"The group with name {group_name} cannot be found."
            )

        # Delete inline policy
        if policy_name not in group.inline_policies:
            raise NoSuchEntityException(
                f"The group policy with name {policy_name} cannot be found."
            )

        del group.inline_policies[policy_name]

    def attach_group_policy(
        self, context: RequestContext, group_name: groupNameType, policy_arn: arnType, **kwargs
    ) -> None:
        """
        Attach a managed policy to a group.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Validate policy ARN
        validate_policy_arn(policy_arn)

        # Verify group exists
        group = store.get_group(group_name)
        if not group:
            raise NoSuchEntityException(
                f"The group with name {group_name} cannot be found."
            )

        # Verify policy exists
        policy = store.get_policy_by_arn(policy_arn)
        if not policy:
            raise NoSuchEntityException(
                f"Policy {policy_arn} does not exist or is not attachable."
            )

        # Check if already attached
        if policy_arn in group.attached_policies:
            return  # No-op if already attached

        # Check attached policies limit
        check_attached_policies_limit(len(group.attached_policies), "group")

        # Attach policy
        group.attached_policies.append(policy_arn)
        policy.attachment_count += 1

    def detach_group_policy(
        self, context: RequestContext, group_name: groupNameType, policy_arn: arnType, **kwargs
    ) -> None:
        """
        Detach a managed policy from a group.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify group exists
        group = store.get_group(group_name)
        if not group:
            raise NoSuchEntityException(
                f"The group with name {group_name} cannot be found."
            )

        # Check if attached
        if policy_arn not in group.attached_policies:
            raise NoSuchEntityException(
                f"Policy {policy_arn} is not attached to group {group_name}."
            )

        # Detach policy
        group.attached_policies.remove(policy_arn)

        # Update policy attachment count
        policy = store.get_policy_by_arn(policy_arn)
        if policy and policy.attachment_count > 0:
            policy.attachment_count -= 1

    def list_attached_group_policies(
        self,
        context: RequestContext,
        group_name: groupNameType,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListAttachedGroupPoliciesResponse:
        """
        List managed policies attached to a group.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify group exists
        group = store.get_group(group_name)
        if not group:
            raise NoSuchEntityException(
                f"The group with name {group_name} cannot be found."
            )

        # Get attached policies
        attached_policies = []
        for policy_arn in group.attached_policies:
            policy = store.get_policy_by_arn(policy_arn)
            if policy:
                # Filter by path prefix if specified
                if path_prefix and not policy.path.startswith(path_prefix):
                    continue
                attached_policies.append(AttachedPolicy(
                    PolicyName=policy.policy_name,
                    PolicyArn=policy.arn,
                ))

        # Sort by policy name
        attached_policies.sort(key=lambda p: p["PolicyName"])

        # Paginate results
        paginated = paginate_list(
            items=attached_policies,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda p: p["PolicyArn"],
        )

        response = ListAttachedGroupPoliciesResponse(
            AttachedPolicies=paginated.items,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    # ------------------------------ Instance Profile Operations ------------------------------ #

    def _instance_profile_to_api_type(
        self,
        profile: InstanceProfileModel,
        store: IamStore,
    ) -> InstanceProfileType:
        """
        Convert internal InstanceProfile model to AWS API InstanceProfile type.

        Native implementation replacing moto.
        """
        # Get the role objects for the instance profile
        roles = []
        for role_name in profile.roles:
            role = store.roles.get(role_name)
            if role:
                role_type = Role(
                    Path=role.path,
                    RoleName=role.role_name,
                    RoleId=role.role_id,
                    Arn=role.arn,
                    CreateDate=role.create_date,
                    AssumeRolePolicyDocument=quote(role.assume_role_policy_document),
                )
                if role.description:
                    role_type["Description"] = role.description
                if role.max_session_duration:
                    role_type["MaxSessionDuration"] = role.max_session_duration
                if role.tags:
                    role_type["Tags"] = tags_to_list(role.tags)
                roles.append(role_type)

        result = InstanceProfileType(
            Path=profile.path,
            InstanceProfileName=profile.instance_profile_name,
            InstanceProfileId=profile.instance_profile_id,
            Arn=profile.arn,
            CreateDate=profile.create_date,
            Roles=roles,
        )
        if profile.tags:
            result["Tags"] = tags_to_list(profile.tags)
        return result

    def create_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        path: pathType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> CreateInstanceProfileResponse:
        """
        Create a new instance profile.

        Native implementation replacing moto.
        """
        # Validate inputs
        validate_instance_profile_name(instance_profile_name)
        path = validate_path(path, "instance profile")

        store = self.get_store(context.account_id, context.region)

        # Check if instance profile already exists
        if instance_profile_name in store.instance_profiles:
            raise EntityAlreadyExistsException(
                f"Instance profile {instance_profile_name} already exists."
            )

        # Generate ID and ARN
        profile_id = generate_instance_profile_id()
        arn = build_instance_profile_arn(context.account_id, path, instance_profile_name)

        # Process tags
        validated_tags = validate_tags(tags) if tags else {}

        # Create the instance profile
        profile = InstanceProfileModel(
            instance_profile_name=instance_profile_name,
            instance_profile_id=profile_id,
            arn=arn,
            path=path,
            tags=validated_tags,
        )

        store.instance_profiles[instance_profile_name] = profile

        return CreateInstanceProfileResponse(
            InstanceProfile=self._instance_profile_to_api_type(profile, store)
        )

    def get_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        **kwargs,
    ) -> GetInstanceProfileResponse:
        """
        Get an instance profile by name.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        profile = store.instance_profiles.get(instance_profile_name)
        if not profile:
            raise NoSuchEntityException(
                f"Instance profile {instance_profile_name} cannot be found."
            )

        return GetInstanceProfileResponse(
            InstanceProfile=self._instance_profile_to_api_type(profile, store)
        )

    def list_instance_profiles(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListInstanceProfilesResponse:
        """
        List instance profiles with optional path prefix filtering.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Get all instance profiles
        all_profiles = list(store.instance_profiles.values())

        # Filter by path prefix
        if path_prefix:
            all_profiles = [p for p in all_profiles if p.path.startswith(path_prefix)]

        # Sort by name
        all_profiles.sort(key=lambda p: p.instance_profile_name)

        # Convert to API types
        api_profiles = [self._instance_profile_to_api_type(p, store) for p in all_profiles]

        # Paginate
        paginated = paginate_list(
            items=api_profiles,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda p: p["InstanceProfileName"],
        )

        response = ListInstanceProfilesResponse(
            InstanceProfiles=paginated.items,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    def delete_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        **kwargs,
    ) -> None:
        """
        Delete an instance profile.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        profile = store.instance_profiles.get(instance_profile_name)
        if not profile:
            raise NoSuchEntityException(
                f"Instance profile {instance_profile_name} cannot be found."
            )

        # Check that no roles are attached
        if profile.roles:
            raise DeleteConflictException(
                f"Cannot delete instance profile {instance_profile_name}. "
                "Remove all roles from the instance profile first."
            )

        del store.instance_profiles[instance_profile_name]

    def add_role_to_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        role_name: roleNameType,
        **kwargs,
    ) -> None:
        """
        Add a role to an instance profile.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Get instance profile
        profile = store.instance_profiles.get(instance_profile_name)
        if not profile:
            raise NoSuchEntityException(
                f"Instance profile {instance_profile_name} cannot be found."
            )

        # Get role
        role = store.roles.get(role_name)
        if not role:
            raise NoSuchEntityException(f"Role {role_name} cannot be found.")

        # Check if role is already attached
        if role_name in profile.roles:
            raise EntityAlreadyExistsException(
                f"Role {role_name} is already associated with instance profile {instance_profile_name}."
            )

        # AWS only allows one role per instance profile
        if profile.roles:
            raise InvalidInputException(
                f"Cannot add role {role_name} to instance profile {instance_profile_name}. "
                "Instance profiles can only have one role."
            )

        profile.roles.append(role_name)

        # Update the role's instance_profiles list
        if instance_profile_name not in role.instance_profiles:
            role.instance_profiles.append(instance_profile_name)

    def remove_role_from_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        role_name: roleNameType,
        **kwargs,
    ) -> None:
        """
        Remove a role from an instance profile.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Get instance profile
        profile = store.instance_profiles.get(instance_profile_name)
        if not profile:
            raise NoSuchEntityException(
                f"Instance profile {instance_profile_name} cannot be found."
            )

        # Check if role is attached
        if role_name not in profile.roles:
            raise NoSuchEntityException(
                f"Role {role_name} is not associated with instance profile {instance_profile_name}."
            )

        profile.roles.remove(role_name)

        # Update the role's instance_profiles list
        role = store.roles.get(role_name)
        if role and instance_profile_name in role.instance_profiles:
            role.instance_profiles.remove(instance_profile_name)

    def list_instance_profiles_for_role(
        self,
        context: RequestContext,
        role_name: roleNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListInstanceProfilesForRoleResponse:
        """
        List instance profiles that contain the specified role.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify role exists
        role = store.roles.get(role_name)
        if not role:
            raise NoSuchEntityException(f"Role {role_name} cannot be found.")

        # Find all instance profiles containing this role
        profiles = [
            p for p in store.instance_profiles.values()
            if role_name in p.roles
        ]

        # Sort by name
        profiles.sort(key=lambda p: p.instance_profile_name)

        # Convert to API types
        api_profiles = [self._instance_profile_to_api_type(p, store) for p in profiles]

        # Paginate
        paginated = paginate_list(
            items=api_profiles,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda p: p["InstanceProfileName"],
        )

        response = ListInstanceProfilesForRoleResponse(
            InstanceProfiles=paginated.items,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    # ------------------------------ Service specific credentials ------------------------------ #

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
        from localstack.services.iam.models import generate_service_specific_credential_id

        return generate_service_specific_credential_id(context.account_id)

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

    def create_service_specific_credential(
        self,
        context: RequestContext,
        user_name: userNameType,
        service_name: serviceName,
        credential_age_days: credentialAgeDays | None = None,
        **kwargs,
    ) -> CreateServiceSpecificCredentialResponse:
        """
        Create a service-specific credential for a user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify user exists
        user = store.users.get(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        self._validate_service_name(service_name)

        # Generate credential
        password = self._generate_service_password()
        credential_id = self._generate_credential_id(context)

        # Store credential in native store
        from localstack.services.iam.models import ServiceSpecificCredential as SSCModel

        credential = SSCModel(
            service_specific_credential_id=credential_id,
            user_name=user_name,
            service_name=service_name,
            service_user_name=f"{user_name}-at-{context.account_id}",
            service_password=password,
            status="Active",
        )

        store.service_specific_credentials[credential_id] = credential
        user.service_specific_credentials.append(credential_id)

        # Return API response format
        return CreateServiceSpecificCredentialResponse(
            ServiceSpecificCredential=ServiceSpecificCredential(
                CreateDate=credential.create_date,
                ServiceName=credential.service_name,
                ServiceUserName=credential.service_user_name,
                ServicePassword=credential.service_password,
                ServiceSpecificCredentialId=credential.service_specific_credential_id,
                UserName=credential.user_name,
                Status=statusType.Active,
            )
        )

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
        """
        List service-specific credentials for a user.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Verify user exists
        user = store.users.get(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        if service_name:
            self._validate_service_name(service_name)

        # Get credentials for user
        result = []
        for cred_id in user.service_specific_credentials:
            cred = store.service_specific_credentials.get(cred_id)
            if cred and (not service_name or cred.service_name == service_name):
                result.append(
                    ServiceSpecificCredentialMetadata(
                        UserName=cred.user_name,
                        Status=statusType(cred.status),
                        ServiceUserName=cred.service_user_name,
                        CreateDate=cred.create_date,
                        ServiceSpecificCredentialId=cred.service_specific_credential_id,
                        ServiceName=cred.service_name,
                    )
                )

        return ListServiceSpecificCredentialsResponse(ServiceSpecificCredentials=result)

    def update_service_specific_credential(
        self,
        context: RequestContext,
        service_specific_credential_id: serviceSpecificCredentialId,
        status: statusType,
        user_name: userNameType = None,
        **kwargs,
    ) -> None:
        """
        Update the status of a service-specific credential.

        Native implementation replacing moto.
        """
        self._validate_status(status)
        self._validate_credential_id(service_specific_credential_id)

        store = self.get_store(context.account_id, context.region)

        # Verify user exists
        user = store.users.get(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        # Find and update credential
        cred = store.service_specific_credentials.get(service_specific_credential_id)
        if not cred or cred.user_name != user_name:
            raise NoSuchEntityException(
                f"No such credential {service_specific_credential_id} exists"
            )

        cred.status = status

    def reset_service_specific_credential(
        self,
        context: RequestContext,
        service_specific_credential_id: serviceSpecificCredentialId,
        user_name: userNameType = None,
        **kwargs,
    ) -> ResetServiceSpecificCredentialResponse:
        """
        Reset the password for a service-specific credential.

        Native implementation replacing moto.
        """
        self._validate_credential_id(service_specific_credential_id)

        store = self.get_store(context.account_id, context.region)

        # Verify user exists
        user = store.users.get(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        # Find credential
        cred = store.service_specific_credentials.get(service_specific_credential_id)
        if not cred or cred.user_name != user_name:
            raise NoSuchEntityException(
                f"No such credential {service_specific_credential_id} exists"
            )

        # Reset password
        cred.service_password = self._generate_service_password()

        return ResetServiceSpecificCredentialResponse(
            ServiceSpecificCredential=ServiceSpecificCredential(
                CreateDate=cred.create_date,
                ServiceName=cred.service_name,
                ServiceUserName=cred.service_user_name,
                ServicePassword=cred.service_password,
                ServiceSpecificCredentialId=cred.service_specific_credential_id,
                UserName=cred.user_name,
                Status=statusType(cred.status),
            )
        )

    def delete_service_specific_credential(
        self,
        context: RequestContext,
        service_specific_credential_id: serviceSpecificCredentialId,
        user_name: userNameType = None,
        **kwargs,
    ) -> None:
        """
        Delete a service-specific credential.

        Native implementation replacing moto.
        """
        self._validate_credential_id(service_specific_credential_id)

        store = self.get_store(context.account_id, context.region)

        # Verify user exists
        user = store.users.get(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        # Find credential
        cred = store.service_specific_credentials.get(service_specific_credential_id)
        if not cred or cred.user_name != user_name:
            raise NoSuchEntityException(
                f"No such credential {service_specific_credential_id} exists"
            )

        # Remove from user and store
        user.service_specific_credentials.remove(service_specific_credential_id)
        del store.service_specific_credentials[service_specific_credential_id]

    # =========================================================================
    # Account Alias Operations (Native Implementation)
    # =========================================================================

    def create_account_alias(
        self,
        context: RequestContext,
        account_alias: accountAliasType,
        **kwargs,
    ) -> None:
        """
        Create an account alias for the AWS account.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Validate alias format (3-63 characters, lowercase alphanumeric and hyphens)
        if not re.match(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", account_alias):
            raise InvalidInputException(
                "Account alias must be between 3 and 63 characters, and can contain "
                "only lowercase letters, digits, and hyphens."
            )

        # Check if alias already exists for this account
        if account_alias in store.account_aliases:
            raise EntityAlreadyExistsException(
                f"The account alias {account_alias} already exists."
            )

        # AWS allows only one alias per account
        if store.account_aliases:
            raise InvalidInputException(
                "An account can have only one alias. Delete the existing alias before creating a new one."
            )

        store.account_aliases.append(account_alias)

    def delete_account_alias(
        self,
        context: RequestContext,
        account_alias: accountAliasType,
        **kwargs,
    ) -> None:
        """
        Delete an account alias.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        if account_alias not in store.account_aliases:
            raise NoSuchEntityException(
                f"The account alias {account_alias} does not exist."
            )

        store.account_aliases.remove(account_alias)

    def list_account_aliases(
        self,
        context: RequestContext,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListAccountAliasesResponse:
        """
        List account aliases for the AWS account.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Paginate results (though typically there's only 0 or 1 alias)
        paginated = paginate_list(
            items=store.account_aliases,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda a: a,
        )

        response = ListAccountAliasesResponse(
            AccountAliases=paginated.items,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker

        return response

    # =========================================================================
    # Password Policy Operations (Native Implementation)
    # =========================================================================

    def update_account_password_policy(
        self,
        context: RequestContext,
        minimum_password_length: minimumPasswordLengthType = None,
        require_symbols: booleanType = None,
        require_numbers: booleanType = None,
        require_uppercase_characters: booleanType = None,
        require_lowercase_characters: booleanType = None,
        allow_users_to_change_password: booleanType = None,
        max_password_age: maxPasswordAgeType = None,
        password_reuse_prevention: passwordReusePreventionType = None,
        hard_expiry: booleanObjectType = None,
        **kwargs,
    ) -> None:
        """
        Update the account password policy.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Validate minimum_password_length (6-128)
        if minimum_password_length is not None:
            if minimum_password_length < 6 or minimum_password_length > 128:
                raise InvalidInputException(
                    "MinimumPasswordLength must be between 6 and 128."
                )

        # Validate max_password_age (0-1095 days)
        if max_password_age is not None:
            if max_password_age < 0 or max_password_age > 1095:
                raise InvalidInputException(
                    "MaxPasswordAge must be between 0 and 1095 days."
                )

        # Validate password_reuse_prevention (0-24)
        if password_reuse_prevention is not None:
            if password_reuse_prevention < 0 or password_reuse_prevention > 24:
                raise InvalidInputException(
                    "PasswordReusePrevention must be between 0 and 24."
                )

        # Create or update password policy
        if store.password_policy is None:
            store.password_policy = PasswordPolicyModel()

        policy = store.password_policy
        if minimum_password_length is not None:
            policy.minimum_password_length = minimum_password_length
        if require_symbols is not None:
            policy.require_symbols = require_symbols
        if require_numbers is not None:
            policy.require_numbers = require_numbers
        if require_uppercase_characters is not None:
            policy.require_uppercase_characters = require_uppercase_characters
        if require_lowercase_characters is not None:
            policy.require_lowercase_characters = require_lowercase_characters
        if allow_users_to_change_password is not None:
            policy.allow_users_to_change_password = allow_users_to_change_password
        if max_password_age is not None:
            policy.max_password_age = max_password_age
            policy.expire_passwords = max_password_age > 0
        if password_reuse_prevention is not None:
            policy.password_reuse_prevention = password_reuse_prevention
        if hard_expiry is not None:
            policy.hard_expiry = hard_expiry

    def get_account_password_policy(
        self,
        context: RequestContext,
        **kwargs,
    ) -> GetAccountPasswordPolicyResponse:
        """
        Get the account password policy.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        if store.password_policy is None:
            raise NoSuchEntityException(
                "The account password policy with name default cannot be found."
            )

        policy = store.password_policy
        return GetAccountPasswordPolicyResponse(
            PasswordPolicy=PasswordPolicyType(
                MinimumPasswordLength=policy.minimum_password_length,
                RequireSymbols=policy.require_symbols,
                RequireNumbers=policy.require_numbers,
                RequireUppercaseCharacters=policy.require_uppercase_characters,
                RequireLowercaseCharacters=policy.require_lowercase_characters,
                AllowUsersToChangePassword=policy.allow_users_to_change_password,
                ExpirePasswords=policy.expire_passwords,
                MaxPasswordAge=policy.max_password_age if policy.expire_passwords else None,
                PasswordReusePrevention=policy.password_reuse_prevention if policy.password_reuse_prevention > 0 else None,
                HardExpiry=policy.hard_expiry,
            )
        )

    def delete_account_password_policy(
        self,
        context: RequestContext,
        **kwargs,
    ) -> None:
        """
        Delete the account password policy.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        if store.password_policy is None:
            raise NoSuchEntityException(
                "The account password policy with name default cannot be found."
            )

        store.password_policy = None

    # =========================================================================
    # Account Summary and Reports (Native Implementation)
    # =========================================================================

    def get_account_summary(
        self,
        context: RequestContext,
        **kwargs,
    ) -> GetAccountSummaryResponse:
        """
        Get account summary statistics.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Count resources
        users_count = len(store.users)
        groups_count = len(store.groups)
        roles_count = len(store.roles)
        policies_count = len(store.policies)
        server_certs_count = len(store.server_certificates)
        mfa_devices_count = len(store.virtual_mfa_devices)

        # Count MFA devices in use
        mfa_devices_in_use = sum(
            1 for user in store.users.values() if user.mfa_devices
        )

        # Count policy versions
        policy_versions_count = sum(
            len(policy.versions) for policy in store.policies.values()
        )

        # Build summary map
        summary_map = {
            summaryKeyType.Users: users_count,
            summaryKeyType.UsersQuota: 5000,
            summaryKeyType.Groups: groups_count,
            summaryKeyType.GroupsQuota: 300,
            summaryKeyType.ServerCertificates: server_certs_count,
            summaryKeyType.ServerCertificatesQuota: 20,
            summaryKeyType.UserPolicySizeQuota: 2048,
            summaryKeyType.GroupPolicySizeQuota: 5120,
            summaryKeyType.GroupsPerUserQuota: 10,
            summaryKeyType.SigningCertificatesPerUserQuota: 2,
            summaryKeyType.AccessKeysPerUserQuota: 2,
            summaryKeyType.MFADevices: mfa_devices_count,
            summaryKeyType.MFADevicesInUse: mfa_devices_in_use,
            summaryKeyType.AccountMFAEnabled: 0,  # Root account MFA not tracked
            summaryKeyType.AccountAccessKeysPresent: 0,  # Root keys not tracked
            summaryKeyType.AccountPasswordPresent: 0,  # Root password not tracked
            summaryKeyType.AccountSigningCertificatesPresent: 0,
            summaryKeyType.AttachedPoliciesPerGroupQuota: 10,
            summaryKeyType.AttachedPoliciesPerRoleQuota: 10,
            summaryKeyType.AttachedPoliciesPerUserQuota: 10,
            summaryKeyType.Policies: policies_count,
            summaryKeyType.PoliciesQuota: 1500,
            summaryKeyType.PolicySizeQuota: 6144,
            summaryKeyType.PolicyVersionsInUse: policy_versions_count,
            summaryKeyType.PolicyVersionsInUseQuota: 10000,
            summaryKeyType.VersionsPerPolicyQuota: 5,
            summaryKeyType.GlobalEndpointTokenVersion: 1,
        }

        return GetAccountSummaryResponse(SummaryMap=summary_map)

    def generate_credential_report(
        self,
        context: RequestContext,
        **kwargs,
    ) -> GenerateCredentialReportResponse:
        """
        Generate a credential report.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Generate report content immediately (simplified for LocalStack)
        # In AWS this is async, but for LocalStack we generate synchronously
        report_content = self._generate_credential_report_content(store, context.account_id)

        # Store the report
        store._credential_report = report_content
        store._credential_report_generated = datetime.utcnow()

        return GenerateCredentialReportResponse(
            State=ReportStateType.COMPLETE,
            Description="Credential report generated successfully",
        )

    def get_credential_report(
        self,
        context: RequestContext,
        **kwargs,
    ) -> GetCredentialReportResponse:
        """
        Get the credential report.

        Native implementation replacing moto.
        """
        store = self.get_store(context.account_id, context.region)

        # Check if report exists
        if not hasattr(store, "_credential_report") or store._credential_report is None:
            raise CredentialReportNotPresentException(
                "Credential report is not present. Use GenerateCredentialReport to generate a report."
            )

        return GetCredentialReportResponse(
            Content=store._credential_report,
            ReportFormat=ReportFormatType.text_csv,
            GeneratedTime=store._credential_report_generated,
        )

    def _generate_credential_report_content(self, store: IamStore, account_id: str) -> bytes:
        """Generate credential report CSV content."""
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow([
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
        ])

        # Add root account row
        writer.writerow([
            "<root_account>",
            f"arn:aws:iam::{account_id}:root",
            "not_supported",
            "not_supported",
            "not_supported",
            "not_supported",
            "not_supported",
            "false",
            "false",
            "N/A",
            "N/A",
            "N/A",
            "N/A",
            "false",
            "N/A",
            "N/A",
            "N/A",
            "N/A",
            "false",
            "N/A",
            "false",
            "N/A",
        ])

        # Add user rows
        for user in store.users.values():
            # Get access keys for user
            user_keys = [store.access_keys.get(kid) for kid in user.access_keys[:2]]
            user_keys = [k for k in user_keys if k]  # Filter None

            # Determine access key info
            ak1_active = "true" if len(user_keys) > 0 and user_keys[0].status == "Active" else "false"
            ak1_rotated = user_keys[0].create_date.isoformat() if len(user_keys) > 0 else "N/A"
            ak2_active = "true" if len(user_keys) > 1 and user_keys[1].status == "Active" else "false"
            ak2_rotated = user_keys[1].create_date.isoformat() if len(user_keys) > 1 else "N/A"

            # Get access key last used info
            ak1_last_used = store.access_key_last_used.get(user_keys[0].access_key_id) if len(user_keys) > 0 else None
            ak2_last_used = store.access_key_last_used.get(user_keys[1].access_key_id) if len(user_keys) > 1 else None

            writer.writerow([
                user.user_name,
                user.arn,
                user.create_date.isoformat(),
                "true" if user.login_profile else "false",
                user.password_last_used.isoformat() if user.password_last_used else "N/A",
                "N/A",  # password_last_changed - not tracked
                "N/A",  # password_next_rotation - not tracked
                "true" if user.mfa_devices else "false",
                ak1_active,
                ak1_rotated,
                ak1_last_used.last_used_date.isoformat() if ak1_last_used and ak1_last_used.last_used_date else "N/A",
                ak1_last_used.region if ak1_last_used and ak1_last_used.region else "N/A",
                ak1_last_used.service_name if ak1_last_used and ak1_last_used.service_name else "N/A",
                ak2_active,
                ak2_rotated,
                ak2_last_used.last_used_date.isoformat() if ak2_last_used and ak2_last_used.last_used_date else "N/A",
                ak2_last_used.region if ak2_last_used and ak2_last_used.region else "N/A",
                ak2_last_used.service_name if ak2_last_used and ak2_last_used.service_name else "N/A",
                "false",  # cert_1_active - not tracked
                "N/A",
                "false",  # cert_2_active - not tracked
                "N/A",
            ])

        return output.getvalue().encode("utf-8")

    def change_password(
        self,
        context: RequestContext,
        old_password: passwordType,
        new_password: passwordType,
        **kwargs,
    ) -> None:
        """
        Change the password for the IAM user making the request.

        Native implementation replacing moto.
        Note: This is a simplified implementation that doesn't actually verify
        the old password since LocalStack doesn't store actual passwords.
        """
        # In a real implementation, we would:
        # 1. Verify the caller's identity from the context
        # 2. Verify the old password matches
        # 3. Validate the new password against the password policy
        # 4. Update the password

        # For LocalStack, we just validate the new password against policy if set
        store = self.get_store(context.account_id, context.region)

        if store.password_policy:
            policy = store.password_policy
            errors = []

            if len(new_password) < policy.minimum_password_length:
                errors.append(f"Password must be at least {policy.minimum_password_length} characters")

            if policy.require_symbols and not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", new_password):
                errors.append("Password must contain at least one symbol")

            if policy.require_numbers and not re.search(r"\d", new_password):
                errors.append("Password must contain at least one number")

            if policy.require_uppercase_characters and not re.search(r"[A-Z]", new_password):
                errors.append("Password must contain at least one uppercase character")

            if policy.require_lowercase_characters and not re.search(r"[a-z]", new_password):
                errors.append("Password must contain at least one lowercase character")

            if errors:
                raise InvalidInputException("; ".join(errors))

    # =========================================================================
    # Policy Tag Operations (Native Implementation)
    # =========================================================================

    def tag_policy(
        self,
        context: RequestContext,
        policy_arn: arnType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        """Tag a managed policy."""
        store = self.get_store(context.account_id, context.region)
        policy = store.get_policy_by_arn(policy_arn)
        if not policy:
            raise NoSuchEntityException(f"Policy {policy_arn} does not exist.")
        if policy_arn.startswith("arn:aws:iam::aws:"):
            raise NoSuchEntityException("Cannot tag AWS managed policies.")
        for tag in tags:
            policy.tags[tag["Key"]] = tag["Value"]

    def untag_policy(
        self,
        context: RequestContext,
        policy_arn: arnType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        """Remove tags from a managed policy."""
        store = self.get_store(context.account_id, context.region)
        policy = store.get_policy_by_arn(policy_arn)
        if not policy:
            raise NoSuchEntityException(f"Policy {policy_arn} does not exist.")
        if policy_arn.startswith("arn:aws:iam::aws:"):
            raise NoSuchEntityException("Cannot untag AWS managed policies.")
        for key in tag_keys:
            policy.tags.pop(key, None)

    def list_policy_tags(
        self,
        context: RequestContext,
        policy_arn: arnType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListPolicyTagsResponse:
        """List tags for a managed policy."""
        store = self.get_store(context.account_id, context.region)
        policy = store.get_policy_by_arn(policy_arn)
        if not policy:
            raise NoSuchEntityException(f"Policy {policy_arn} does not exist.")

        tags = [{"Key": k, "Value": v} for k, v in policy.tags.items()]
        paginated = paginate_list(
            items=tags,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda t: t["Key"],
        )

        response = ListPolicyTagsResponse(
            Tags=paginated.items,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker
        return response

    def list_entities_for_policy(
        self,
        context: RequestContext,
        policy_arn: arnType,
        entity_filter: EntityType = None,
        path_prefix: pathPrefixType = None,
        policy_usage_filter: policyScopeType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListEntitiesForPolicyResponse:
        """List all IAM entities that have the specified policy attached."""
        store = self.get_store(context.account_id, context.region)
        policy = store.get_policy_by_arn(policy_arn)
        if not policy:
            raise NoSuchEntityException(f"Policy {policy_arn} does not exist.")

        policy_groups = []
        policy_users = []
        policy_roles = []

        # Find users with this policy attached
        if entity_filter is None or entity_filter == EntityType.User:
            for user in store.users.values():
                if policy_arn in user.attached_policies:
                    if path_prefix and not user.path.startswith(path_prefix):
                        continue
                    policy_users.append(PolicyUser(UserName=user.user_name, UserId=user.user_id))

        # Find groups with this policy attached
        if entity_filter is None or entity_filter == EntityType.Group:
            for group in store.groups.values():
                if policy_arn in group.attached_policies:
                    if path_prefix and not group.path.startswith(path_prefix):
                        continue
                    policy_groups.append(PolicyGroup(GroupName=group.group_name, GroupId=group.group_id))

        # Find roles with this policy attached
        if entity_filter is None or entity_filter == EntityType.Role:
            for role in store.roles.values():
                if policy_arn in role.attached_policies:
                    if path_prefix and not role.path.startswith(path_prefix):
                        continue
                    policy_roles.append(PolicyRole(RoleName=role.role_name, RoleId=role.role_id))

        return ListEntitiesForPolicyResponse(
            PolicyGroups=policy_groups,
            PolicyUsers=policy_users,
            PolicyRoles=policy_roles,
            IsTruncated=False,
        )

    # =========================================================================
    # MFA Device Operations (Native Implementation)
    # =========================================================================

    def create_virtual_mfa_device(
        self,
        context: RequestContext,
        virtual_mfa_device_name: virtualMFADeviceName,
        path: pathType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> CreateVirtualMFADeviceResponse:
        """Create a virtual MFA device."""
        import base64
        import secrets
        import string

        store = self.get_store(context.account_id, context.region)
        path = path or "/"

        # Build the serial number (ARN)
        serial_number = build_mfa_device_arn(context.account_id, virtual_mfa_device_name)

        # Check if device already exists
        if serial_number in store.virtual_mfa_devices:
            raise EntityAlreadyExistsException(
                f"MFA device with serial number {serial_number} already exists."
            )

        # Generate TOTP seed using standard library (base32 alphabet: A-Z, 2-7)
        base32_chars = string.ascii_uppercase + "234567"
        base32_seed = "".join(secrets.choice(base32_chars) for _ in range(32))
        qr_code_png = None  # Simplified - not generating actual QR code

        # Create the device
        device = VirtualMFADeviceModel(
            serial_number=serial_number,
            base32_string_seed=base32_seed,
            qr_code_png=qr_code_png,
            tags={tag["Key"]: tag["Value"] for tag in (tags or [])},
        )
        store.virtual_mfa_devices[serial_number] = device

        response_device = VirtualMFADeviceType(
            SerialNumber=serial_number,
            Base32StringSeed=base32_seed.encode(),
        )
        if qr_code_png:
            response_device["QRCodePNG"] = qr_code_png

        return CreateVirtualMFADeviceResponse(VirtualMFADevice=response_device)

    def delete_virtual_mfa_device(
        self,
        context: RequestContext,
        serial_number: serialNumberType,
        **kwargs,
    ) -> None:
        """Delete a virtual MFA device."""
        store = self.get_store(context.account_id, context.region)

        if serial_number not in store.virtual_mfa_devices:
            raise NoSuchEntityException(
                f"MFA device with serial number {serial_number} does not exist."
            )

        device = store.virtual_mfa_devices[serial_number]

        # If device is assigned to a user, remove it from the user
        if device.user_name:
            user = store.get_user(device.user_name)
            if user and serial_number in user.mfa_devices:
                user.mfa_devices.remove(serial_number)

        del store.virtual_mfa_devices[serial_number]

    def list_virtual_mfa_devices(
        self,
        context: RequestContext,
        assignment_status: assignmentStatusType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListVirtualMFADevicesResponse:
        """List virtual MFA devices."""
        store = self.get_store(context.account_id, context.region)

        devices = list(store.virtual_mfa_devices.values())

        # Filter by assignment status
        if assignment_status == "Assigned":
            devices = [d for d in devices if d.user_name is not None]
        elif assignment_status == "Unassigned":
            devices = [d for d in devices if d.user_name is None]

        # Paginate
        paginated = paginate_list(
            items=devices,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda d: d.serial_number,
        )

        mfa_devices = []
        for device in paginated.items:
            mfa_device = VirtualMFADeviceType(SerialNumber=device.serial_number)
            if device.user_arn:
                mfa_device["User"] = User(
                    UserName=device.user_name,
                    Arn=device.user_arn,
                    UserId="",
                    Path="/",
                    CreateDate=datetime.utcnow(),
                )
            if device.enable_date:
                mfa_device["EnableDate"] = device.enable_date
            mfa_devices.append(mfa_device)

        response = ListVirtualMFADevicesResponse(
            VirtualMFADevices=mfa_devices,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker
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
        """Enable an MFA device for a user."""
        store = self.get_store(context.account_id, context.region)

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        if serial_number not in store.virtual_mfa_devices:
            raise NoSuchEntityException(
                f"MFA device with serial number {serial_number} does not exist."
            )

        device = store.virtual_mfa_devices[serial_number]

        if device.user_name:
            raise EntityAlreadyExistsException(
                f"MFA device {serial_number} is already assigned to user {device.user_name}."
            )

        # In a real implementation, we would validate the authentication codes
        # For LocalStack, we just enable the device
        device.user_name = user_name
        device.user_arn = user.arn
        device.enable_date = datetime.utcnow()
        device.base32_string_seed = None  # Clear seed after enabling

        if serial_number not in user.mfa_devices:
            user.mfa_devices.append(serial_number)

    def deactivate_mfa_device(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        serial_number: serialNumberType,
        **kwargs,
    ) -> None:
        """Deactivate an MFA device from a user."""
        store = self.get_store(context.account_id, context.region)

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        if serial_number not in store.virtual_mfa_devices:
            raise NoSuchEntityException(
                f"MFA device with serial number {serial_number} does not exist."
            )

        device = store.virtual_mfa_devices[serial_number]

        if device.user_name != user_name:
            raise NoSuchEntityException(
                f"MFA device {serial_number} is not assigned to user {user_name}."
            )

        # Deactivate the device
        device.user_name = None
        device.user_arn = None
        device.enable_date = None

        if serial_number in user.mfa_devices:
            user.mfa_devices.remove(serial_number)

    def resync_mfa_device(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        serial_number: serialNumberType,
        authentication_code1: authenticationCodeType,
        authentication_code2: authenticationCodeType,
        **kwargs,
    ) -> None:
        """Resync an MFA device."""
        store = self.get_store(context.account_id, context.region)

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        if serial_number not in store.virtual_mfa_devices:
            raise NoSuchEntityException(
                f"MFA device with serial number {serial_number} does not exist."
            )

        device = store.virtual_mfa_devices[serial_number]

        if device.user_name != user_name:
            raise NoSuchEntityException(
                f"MFA device {serial_number} is not assigned to user {user_name}."
            )

        # In a real implementation, we would validate and resync the device
        # For LocalStack, this is a no-op

    def list_mfa_devices(
        self,
        context: RequestContext,
        user_name: existingUserNameType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListMFADevicesResponse:
        """List MFA devices for a user."""
        store = self.get_store(context.account_id, context.region)

        # If no user specified, use caller identity (simplified for LocalStack)
        if user_name:
            user = store.get_user(user_name)
            if not user:
                raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")
            device_serials = user.mfa_devices
        else:
            device_serials = []

        mfa_devices = []
        for serial in device_serials:
            device = store.virtual_mfa_devices.get(serial)
            if device and device.enable_date:
                mfa_devices.append(MFADevice(
                    UserName=user_name,
                    SerialNumber=serial,
                    EnableDate=device.enable_date,
                ))

        return ListMFADevicesResponse(
            MFADevices=mfa_devices,
            IsTruncated=False,
        )

    def tag_mfa_device(
        self,
        context: RequestContext,
        serial_number: serialNumberType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        """Tag a virtual MFA device."""
        store = self.get_store(context.account_id, context.region)

        if serial_number not in store.virtual_mfa_devices:
            raise NoSuchEntityException(
                f"MFA device with serial number {serial_number} does not exist."
            )

        device = store.virtual_mfa_devices[serial_number]
        for tag in tags:
            device.tags[tag["Key"]] = tag["Value"]

    def untag_mfa_device(
        self,
        context: RequestContext,
        serial_number: serialNumberType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        """Untag a virtual MFA device."""
        store = self.get_store(context.account_id, context.region)

        if serial_number not in store.virtual_mfa_devices:
            raise NoSuchEntityException(
                f"MFA device with serial number {serial_number} does not exist."
            )

        device = store.virtual_mfa_devices[serial_number]
        for key in tag_keys:
            device.tags.pop(key, None)

    # =========================================================================
    # OIDC Provider Operations (Native Implementation)
    # =========================================================================

    def create_open_id_connect_provider(
        self,
        context: RequestContext,
        url: OpenIDConnectProviderUrlType,
        thumbprint_list: thumbprintListType,
        client_id_list: clientIDListType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> CreateOpenIDConnectProviderResponse:
        """Create an OIDC identity provider."""
        store = self.get_store(context.account_id, context.region)

        # Normalize URL (remove trailing slash)
        normalized_url = url.rstrip("/")
        arn = build_oidc_provider_arn(context.account_id, normalized_url)

        if arn in store.oidc_providers:
            raise EntityAlreadyExistsException(
                f"OIDC Provider with URL {url} already exists."
            )

        provider = OIDCProviderModel(
            arn=arn,
            url=normalized_url,
            client_id_list=client_id_list or [],
            thumbprint_list=thumbprint_list,
            tags={tag["Key"]: tag["Value"] for tag in (tags or [])},
        )
        store.oidc_providers[arn] = provider

        response = CreateOpenIDConnectProviderResponse(OpenIDConnectProviderArn=arn)
        if tags:
            response["Tags"] = tags
        return response

    def get_open_id_connect_provider(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        **kwargs,
    ) -> GetOpenIDConnectProviderResponse:
        """Get an OIDC identity provider."""
        store = self.get_store(context.account_id, context.region)

        provider = store.oidc_providers.get(open_id_connect_provider_arn)
        if not provider:
            raise NoSuchEntityException(
                f"OIDC Provider {open_id_connect_provider_arn} does not exist."
            )

        response = GetOpenIDConnectProviderResponse(
            Url=provider.url,
            ClientIDList=provider.client_id_list,
            ThumbprintList=provider.thumbprint_list,
            CreateDate=provider.create_date,
        )
        if provider.tags:
            response["Tags"] = [{"Key": k, "Value": v} for k, v in provider.tags.items()]
        return response

    def list_open_id_connect_providers(
        self,
        context: RequestContext,
        **kwargs,
    ) -> ListOpenIDConnectProvidersResponse:
        """List OIDC identity providers."""
        store = self.get_store(context.account_id, context.region)

        providers = [
            OpenIDConnectProviderListEntry(Arn=p.arn)
            for p in store.oidc_providers.values()
        ]

        return ListOpenIDConnectProvidersResponse(OpenIDConnectProviderList=providers)

    def delete_open_id_connect_provider(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        **kwargs,
    ) -> None:
        """Delete an OIDC identity provider."""
        store = self.get_store(context.account_id, context.region)

        if open_id_connect_provider_arn not in store.oidc_providers:
            raise NoSuchEntityException(
                f"OIDC Provider {open_id_connect_provider_arn} does not exist."
            )

        del store.oidc_providers[open_id_connect_provider_arn]

    def add_client_id_to_open_id_connect_provider(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        client_id: clientIDType,
        **kwargs,
    ) -> None:
        """Add a client ID to an OIDC provider."""
        store = self.get_store(context.account_id, context.region)

        provider = store.oidc_providers.get(open_id_connect_provider_arn)
        if not provider:
            raise NoSuchEntityException(
                f"OIDC Provider {open_id_connect_provider_arn} does not exist."
            )

        if client_id in provider.client_id_list:
            raise EntityAlreadyExistsException(
                f"Client ID {client_id} already exists in OIDC provider."
            )

        if len(provider.client_id_list) >= 100:
            raise LimitExceededException("Cannot exceed 100 client IDs per OIDC provider.")

        provider.client_id_list.append(client_id)

    def remove_client_id_from_open_id_connect_provider(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        client_id: clientIDType,
        **kwargs,
    ) -> None:
        """Remove a client ID from an OIDC provider."""
        store = self.get_store(context.account_id, context.region)

        provider = store.oidc_providers.get(open_id_connect_provider_arn)
        if not provider:
            raise NoSuchEntityException(
                f"OIDC Provider {open_id_connect_provider_arn} does not exist."
            )

        if client_id not in provider.client_id_list:
            raise NoSuchEntityException(
                f"Client ID {client_id} not found in OIDC provider."
            )

        provider.client_id_list.remove(client_id)

    def update_open_id_connect_provider_thumbprint(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        thumbprint_list: thumbprintListType,
        **kwargs,
    ) -> None:
        """Update thumbprints for an OIDC provider."""
        store = self.get_store(context.account_id, context.region)

        provider = store.oidc_providers.get(open_id_connect_provider_arn)
        if not provider:
            raise NoSuchEntityException(
                f"OIDC Provider {open_id_connect_provider_arn} does not exist."
            )

        provider.thumbprint_list = thumbprint_list

    def tag_open_id_connect_provider(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        """Tag an OIDC provider."""
        store = self.get_store(context.account_id, context.region)

        provider = store.oidc_providers.get(open_id_connect_provider_arn)
        if not provider:
            raise NoSuchEntityException(
                f"OIDC Provider {open_id_connect_provider_arn} does not exist."
            )

        for tag in tags:
            provider.tags[tag["Key"]] = tag["Value"]

    def untag_open_id_connect_provider(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        """Untag an OIDC provider."""
        store = self.get_store(context.account_id, context.region)

        provider = store.oidc_providers.get(open_id_connect_provider_arn)
        if not provider:
            raise NoSuchEntityException(
                f"OIDC Provider {open_id_connect_provider_arn} does not exist."
            )

        for key in tag_keys:
            provider.tags.pop(key, None)

    def list_open_id_connect_provider_tags(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListOpenIDConnectProviderTagsResponse:
        """List tags for an OIDC provider."""
        store = self.get_store(context.account_id, context.region)

        provider = store.oidc_providers.get(open_id_connect_provider_arn)
        if not provider:
            raise NoSuchEntityException(
                f"OIDC Provider {open_id_connect_provider_arn} does not exist."
            )

        tags = [{"Key": k, "Value": v} for k, v in provider.tags.items()]
        return ListOpenIDConnectProviderTagsResponse(Tags=tags, IsTruncated=False)

    # =========================================================================
    # SAML Provider Operations (Native Implementation)
    # =========================================================================

    def create_saml_provider(
        self,
        context: RequestContext,
        saml_metadata_document: SAMLMetadataDocumentType,
        name: SAMLProviderNameType,
        tags: tagListType = None,
        **kwargs,
    ) -> CreateSAMLProviderResponse:
        """Create a SAML identity provider."""
        store = self.get_store(context.account_id, context.region)

        arn = build_saml_provider_arn(context.account_id, name)

        if arn in store.saml_providers:
            raise EntityAlreadyExistsException(
                f"SAML Provider {name} already exists."
            )

        provider = SAMLProviderModel(
            arn=arn,
            name=name,
            saml_metadata_document=saml_metadata_document,
            tags={tag["Key"]: tag["Value"] for tag in (tags or [])},
        )
        store.saml_providers[arn] = provider

        response = CreateSAMLProviderResponse(SAMLProviderArn=arn)
        if tags:
            response["Tags"] = tags
        return response

    def get_saml_provider(
        self,
        context: RequestContext,
        saml_provider_arn: arnType,
        **kwargs,
    ) -> GetSAMLProviderResponse:
        """Get a SAML identity provider."""
        store = self.get_store(context.account_id, context.region)

        provider = store.saml_providers.get(saml_provider_arn)
        if not provider:
            raise NoSuchEntityException(
                f"SAML Provider {saml_provider_arn} does not exist."
            )

        response = GetSAMLProviderResponse(
            SAMLMetadataDocument=provider.saml_metadata_document,
            CreateDate=provider.create_date,
        )
        if provider.valid_until:
            response["ValidUntil"] = provider.valid_until
        if provider.tags:
            response["Tags"] = [{"Key": k, "Value": v} for k, v in provider.tags.items()]
        return response

    def list_saml_providers(
        self,
        context: RequestContext,
        **kwargs,
    ) -> ListSAMLProvidersResponse:
        """List SAML identity providers."""
        store = self.get_store(context.account_id, context.region)

        providers = [
            SAMLProviderListEntry(
                Arn=p.arn,
                ValidUntil=p.valid_until,
                CreateDate=p.create_date,
            )
            for p in store.saml_providers.values()
        ]

        return ListSAMLProvidersResponse(SAMLProviderList=providers)

    def update_saml_provider(
        self,
        context: RequestContext,
        saml_metadata_document: SAMLMetadataDocumentType,
        saml_provider_arn: arnType,
        **kwargs,
    ) -> UpdateSAMLProviderResponse:
        """Update a SAML identity provider."""
        store = self.get_store(context.account_id, context.region)

        provider = store.saml_providers.get(saml_provider_arn)
        if not provider:
            raise NoSuchEntityException(
                f"SAML Provider {saml_provider_arn} does not exist."
            )

        provider.saml_metadata_document = saml_metadata_document

        return UpdateSAMLProviderResponse(SAMLProviderArn=saml_provider_arn)

    def delete_saml_provider(
        self,
        context: RequestContext,
        saml_provider_arn: arnType,
        **kwargs,
    ) -> None:
        """Delete a SAML identity provider."""
        store = self.get_store(context.account_id, context.region)

        if saml_provider_arn not in store.saml_providers:
            raise NoSuchEntityException(
                f"SAML Provider {saml_provider_arn} does not exist."
            )

        del store.saml_providers[saml_provider_arn]

    def tag_saml_provider(
        self,
        context: RequestContext,
        saml_provider_arn: arnType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        """Tag a SAML provider."""
        store = self.get_store(context.account_id, context.region)

        provider = store.saml_providers.get(saml_provider_arn)
        if not provider:
            raise NoSuchEntityException(
                f"SAML Provider {saml_provider_arn} does not exist."
            )

        for tag in tags:
            provider.tags[tag["Key"]] = tag["Value"]

    def untag_saml_provider(
        self,
        context: RequestContext,
        saml_provider_arn: arnType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        """Untag a SAML provider."""
        store = self.get_store(context.account_id, context.region)

        provider = store.saml_providers.get(saml_provider_arn)
        if not provider:
            raise NoSuchEntityException(
                f"SAML Provider {saml_provider_arn} does not exist."
            )

        for key in tag_keys:
            provider.tags.pop(key, None)

    def list_saml_provider_tags(
        self,
        context: RequestContext,
        saml_provider_arn: arnType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListSAMLProviderTagsResponse:
        """List tags for a SAML provider."""
        store = self.get_store(context.account_id, context.region)

        provider = store.saml_providers.get(saml_provider_arn)
        if not provider:
            raise NoSuchEntityException(
                f"SAML Provider {saml_provider_arn} does not exist."
            )

        tags = [{"Key": k, "Value": v} for k, v in provider.tags.items()]
        return ListSAMLProviderTagsResponse(Tags=tags, IsTruncated=False)

    # =========================================================================
    # Server Certificate Operations (Native Implementation)
    # =========================================================================

    def upload_server_certificate(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        certificate_body: certificateBodyType,
        private_key: privateKeyType,
        path: pathType = None,
        certificate_chain: certificateChainType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> UploadServerCertificateResponse:
        """Upload a server certificate."""
        store = self.get_store(context.account_id, context.region)
        path = path or "/"

        if server_certificate_name in store.server_certificates:
            raise EntityAlreadyExistsException(
                f"Server certificate {server_certificate_name} already exists."
            )

        cert_id = generate_server_certificate_id()
        arn = build_server_certificate_arn(context.account_id, path, server_certificate_name)

        # Try to parse expiration from certificate
        expiration = None
        try:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(certificate_body.encode())
            expiration = cert.not_valid_after_utc
        except Exception:
            pass

        certificate = ServerCertificateModel(
            server_certificate_name=server_certificate_name,
            server_certificate_id=cert_id,
            arn=arn,
            path=path,
            certificate_body=certificate_body,
            certificate_chain=certificate_chain,
            expiration=expiration,
            tags={tag["Key"]: tag["Value"] for tag in (tags or [])},
        )
        store.server_certificates[server_certificate_name] = certificate

        metadata = ServerCertificateMetadata(
            ServerCertificateName=server_certificate_name,
            ServerCertificateId=cert_id,
            Arn=arn,
            Path=path,
            UploadDate=certificate.upload_date,
        )
        if expiration:
            metadata["Expiration"] = expiration

        response = UploadServerCertificateResponse(ServerCertificateMetadata=metadata)
        if tags:
            response["Tags"] = tags
        return response

    def get_server_certificate(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        **kwargs,
    ) -> GetServerCertificateResponse:
        """Get a server certificate."""
        store = self.get_store(context.account_id, context.region)

        cert = store.server_certificates.get(server_certificate_name)
        if not cert:
            raise NoSuchEntityException(
                f"Server certificate {server_certificate_name} does not exist."
            )

        metadata = ServerCertificateMetadata(
            ServerCertificateName=cert.server_certificate_name,
            ServerCertificateId=cert.server_certificate_id,
            Arn=cert.arn,
            Path=cert.path,
            UploadDate=cert.upload_date,
        )
        if cert.expiration:
            metadata["Expiration"] = cert.expiration

        server_cert = ServerCertificate(
            ServerCertificateMetadata=metadata,
            CertificateBody=cert.certificate_body,
        )
        if cert.certificate_chain:
            server_cert["CertificateChain"] = cert.certificate_chain
        if cert.tags:
            server_cert["Tags"] = [{"Key": k, "Value": v} for k, v in cert.tags.items()]

        return GetServerCertificateResponse(ServerCertificate=server_cert)

    def list_server_certificates(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListServerCertificatesResponse:
        """List server certificates."""
        store = self.get_store(context.account_id, context.region)

        certs = list(store.server_certificates.values())
        if path_prefix:
            certs = [c for c in certs if c.path.startswith(path_prefix)]

        paginated = paginate_list(
            items=certs,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda c: c.server_certificate_name,
        )

        metadata_list = []
        for cert in paginated.items:
            metadata = ServerCertificateMetadata(
                ServerCertificateName=cert.server_certificate_name,
                ServerCertificateId=cert.server_certificate_id,
                Arn=cert.arn,
                Path=cert.path,
                UploadDate=cert.upload_date,
            )
            if cert.expiration:
                metadata["Expiration"] = cert.expiration
            metadata_list.append(metadata)

        response = ListServerCertificatesResponse(
            ServerCertificateMetadataList=metadata_list,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker
        return response

    def delete_server_certificate(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        **kwargs,
    ) -> None:
        """Delete a server certificate."""
        store = self.get_store(context.account_id, context.region)

        if server_certificate_name not in store.server_certificates:
            raise NoSuchEntityException(
                f"Server certificate {server_certificate_name} does not exist."
            )

        del store.server_certificates[server_certificate_name]

    def update_server_certificate(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        new_path: pathType = None,
        new_server_certificate_name: serverCertificateNameType = None,
        **kwargs,
    ) -> None:
        """Update a server certificate."""
        store = self.get_store(context.account_id, context.region)

        cert = store.server_certificates.get(server_certificate_name)
        if not cert:
            raise NoSuchEntityException(
                f"Server certificate {server_certificate_name} does not exist."
            )

        if new_server_certificate_name and new_server_certificate_name != server_certificate_name:
            if new_server_certificate_name in store.server_certificates:
                raise EntityAlreadyExistsException(
                    f"Server certificate {new_server_certificate_name} already exists."
                )
            del store.server_certificates[server_certificate_name]
            cert.server_certificate_name = new_server_certificate_name
            store.server_certificates[new_server_certificate_name] = cert

        if new_path:
            cert.path = new_path
            cert.arn = build_server_certificate_arn(
                context.account_id, new_path, cert.server_certificate_name
            )

    def tag_server_certificate(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        """Tag a server certificate."""
        store = self.get_store(context.account_id, context.region)

        cert = store.server_certificates.get(server_certificate_name)
        if not cert:
            raise NoSuchEntityException(
                f"Server certificate {server_certificate_name} does not exist."
            )

        for tag in tags:
            cert.tags[tag["Key"]] = tag["Value"]

    def untag_server_certificate(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        """Untag a server certificate."""
        store = self.get_store(context.account_id, context.region)

        cert = store.server_certificates.get(server_certificate_name)
        if not cert:
            raise NoSuchEntityException(
                f"Server certificate {server_certificate_name} does not exist."
            )

        for key in tag_keys:
            cert.tags.pop(key, None)

    def list_server_certificate_tags(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListServerCertificateTagsResponse:
        """List tags for a server certificate."""
        store = self.get_store(context.account_id, context.region)

        cert = store.server_certificates.get(server_certificate_name)
        if not cert:
            raise NoSuchEntityException(
                f"Server certificate {server_certificate_name} does not exist."
            )

        tags = [{"Key": k, "Value": v} for k, v in cert.tags.items()]
        return ListServerCertificateTagsResponse(Tags=tags, IsTruncated=False)

    # =========================================================================
    # SSH Public Key Operations (Native Implementation)
    # =========================================================================

    def upload_ssh_public_key(
        self,
        context: RequestContext,
        user_name: userNameType,
        ssh_public_key_body: publicKeyMaterialType,
        **kwargs,
    ) -> UploadSSHPublicKeyResponse:
        """Upload an SSH public key for a user."""
        import hashlib

        store = self.get_store(context.account_id, context.region)

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        # Check limit (5 SSH keys per user)
        if len(user.ssh_public_keys) >= 5:
            raise LimitExceededException("Cannot exceed 5 SSH public keys per user.")

        key_id = generate_ssh_public_key_id()

        # Generate fingerprint (simplified MD5 hash of the key)
        fingerprint = hashlib.md5(ssh_public_key_body.encode()).hexdigest()
        fingerprint = ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))

        ssh_key = SSHPublicKeyModel(
            ssh_public_key_id=key_id,
            user_name=user_name,
            ssh_public_key_body=ssh_public_key_body,
            fingerprint=fingerprint,
        )
        store.ssh_public_keys[key_id] = ssh_key
        user.ssh_public_keys.append(key_id)

        return UploadSSHPublicKeyResponse(
            SSHPublicKey=SSHPublicKey(
                UserName=user_name,
                SSHPublicKeyId=key_id,
                Fingerprint=fingerprint,
                SSHPublicKeyBody=ssh_public_key_body,
                Status=ssh_key.status,
                UploadDate=ssh_key.upload_date,
            )
        )

    def get_ssh_public_key(
        self,
        context: RequestContext,
        user_name: userNameType,
        ssh_public_key_id: publicKeyIdType,
        encoding: encodingType,
        **kwargs,
    ) -> GetSSHPublicKeyResponse:
        """Get an SSH public key."""
        store = self.get_store(context.account_id, context.region)

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        if ssh_public_key_id not in store.ssh_public_keys:
            raise NoSuchEntityException(f"SSH public key {ssh_public_key_id} does not exist.")

        ssh_key = store.ssh_public_keys[ssh_public_key_id]
        if ssh_key.user_name != user_name:
            raise NoSuchEntityException(f"SSH public key {ssh_public_key_id} does not belong to user {user_name}.")

        return GetSSHPublicKeyResponse(
            SSHPublicKey=SSHPublicKey(
                UserName=user_name,
                SSHPublicKeyId=ssh_public_key_id,
                Fingerprint=ssh_key.fingerprint,
                SSHPublicKeyBody=ssh_key.ssh_public_key_body,
                Status=ssh_key.status,
                UploadDate=ssh_key.upload_date,
            )
        )

    def list_ssh_public_keys(
        self,
        context: RequestContext,
        user_name: userNameType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListSSHPublicKeysResponse:
        """List SSH public keys for a user."""
        store = self.get_store(context.account_id, context.region)

        if user_name:
            user = store.get_user(user_name)
            if not user:
                raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")
            key_ids = user.ssh_public_keys
        else:
            key_ids = list(store.ssh_public_keys.keys())

        keys = [store.ssh_public_keys[kid] for kid in key_ids if kid in store.ssh_public_keys]

        paginated = paginate_list(
            items=keys,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda k: k.ssh_public_key_id,
        )

        metadata_list = [
            SSHPublicKeyMetadata(
                UserName=k.user_name,
                SSHPublicKeyId=k.ssh_public_key_id,
                Status=k.status,
                UploadDate=k.upload_date,
            )
            for k in paginated.items
        ]

        response = ListSSHPublicKeysResponse(
            SSHPublicKeys=metadata_list,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker
        return response

    def update_ssh_public_key(
        self,
        context: RequestContext,
        user_name: userNameType,
        ssh_public_key_id: publicKeyIdType,
        status: statusType,
        **kwargs,
    ) -> None:
        """Update an SSH public key status."""
        store = self.get_store(context.account_id, context.region)

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        if ssh_public_key_id not in store.ssh_public_keys:
            raise NoSuchEntityException(f"SSH public key {ssh_public_key_id} does not exist.")

        ssh_key = store.ssh_public_keys[ssh_public_key_id]
        if ssh_key.user_name != user_name:
            raise NoSuchEntityException(f"SSH public key {ssh_public_key_id} does not belong to user {user_name}.")

        ssh_key.status = status

    def delete_ssh_public_key(
        self,
        context: RequestContext,
        user_name: userNameType,
        ssh_public_key_id: publicKeyIdType,
        **kwargs,
    ) -> None:
        """Delete an SSH public key."""
        store = self.get_store(context.account_id, context.region)

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        if ssh_public_key_id not in store.ssh_public_keys:
            raise NoSuchEntityException(f"SSH public key {ssh_public_key_id} does not exist.")

        ssh_key = store.ssh_public_keys[ssh_public_key_id]
        if ssh_key.user_name != user_name:
            raise NoSuchEntityException(f"SSH public key {ssh_public_key_id} does not belong to user {user_name}.")

        del store.ssh_public_keys[ssh_public_key_id]
        if ssh_public_key_id in user.ssh_public_keys:
            user.ssh_public_keys.remove(ssh_public_key_id)

    # =========================================================================
    # Signing Certificate Operations (Native Implementation)
    # =========================================================================

    def upload_signing_certificate(
        self,
        context: RequestContext,
        certificate_body: certificateBodyType,
        user_name: existingUserNameType = None,
        **kwargs,
    ) -> UploadSigningCertificateResponse:
        """Upload a signing certificate for a user."""
        store = self.get_store(context.account_id, context.region)

        # If no user specified, use caller identity (simplified for LocalStack)
        if not user_name:
            raise InvalidInputException("UserName is required.")

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        # Check limit (2 signing certificates per user)
        if len(user.signing_certificates) >= 2:
            raise LimitExceededException("Cannot exceed 2 signing certificates per user.")

        cert_id = generate_certificate_id()

        signing_cert = SigningCertificateModel(
            certificate_id=cert_id,
            user_name=user_name,
            certificate_body=certificate_body,
        )
        store.signing_certificates[cert_id] = signing_cert
        user.signing_certificates.append(cert_id)

        return UploadSigningCertificateResponse(
            Certificate=SigningCertificateType(
                UserName=user_name,
                CertificateId=cert_id,
                CertificateBody=certificate_body,
                Status=signing_cert.status,
                UploadDate=signing_cert.upload_date,
            )
        )

    def list_signing_certificates(
        self,
        context: RequestContext,
        user_name: existingUserNameType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListSigningCertificatesResponse:
        """List signing certificates for a user."""
        store = self.get_store(context.account_id, context.region)

        if not user_name:
            raise InvalidInputException("UserName is required.")

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        certs = [store.signing_certificates[cid] for cid in user.signing_certificates if cid in store.signing_certificates]

        paginated = paginate_list(
            items=certs,
            marker=marker,
            max_items=max_items,
            get_marker_value=lambda c: c.certificate_id,
        )

        cert_list = [
            SigningCertificateType(
                UserName=c.user_name,
                CertificateId=c.certificate_id,
                CertificateBody=c.certificate_body,
                Status=c.status,
                UploadDate=c.upload_date,
            )
            for c in paginated.items
        ]

        response = ListSigningCertificatesResponse(
            Certificates=cert_list,
            IsTruncated=paginated.is_truncated,
        )
        if paginated.next_marker:
            response["Marker"] = paginated.next_marker
        return response

    def update_signing_certificate(
        self,
        context: RequestContext,
        certificate_id: certificateIdType,
        status: statusType,
        user_name: existingUserNameType = None,
        **kwargs,
    ) -> None:
        """Update a signing certificate status."""
        store = self.get_store(context.account_id, context.region)

        if not user_name:
            raise InvalidInputException("UserName is required.")

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        if certificate_id not in store.signing_certificates:
            raise NoSuchEntityException(f"Signing certificate {certificate_id} does not exist.")

        cert = store.signing_certificates[certificate_id]
        if cert.user_name != user_name:
            raise NoSuchEntityException(f"Signing certificate {certificate_id} does not belong to user {user_name}.")

        cert.status = status

    def delete_signing_certificate(
        self,
        context: RequestContext,
        certificate_id: certificateIdType,
        user_name: existingUserNameType = None,
        **kwargs,
    ) -> None:
        """Delete a signing certificate."""
        store = self.get_store(context.account_id, context.region)

        if not user_name:
            raise InvalidInputException("UserName is required.")

        user = store.get_user(user_name)
        if not user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")

        if certificate_id not in store.signing_certificates:
            raise NoSuchEntityException(f"Signing certificate {certificate_id} does not exist.")

        cert = store.signing_certificates[certificate_id]
        if cert.user_name != user_name:
            raise NoSuchEntityException(f"Signing certificate {certificate_id} does not belong to user {user_name}.")

        del store.signing_certificates[certificate_id]
        if certificate_id in user.signing_certificates:
            user.signing_certificates.remove(certificate_id)

    # =========================================================================
    # Policy Simulation Operations (Native Implementation - Stub)
    # =========================================================================

    def simulate_custom_policy(
        self,
        context: RequestContext,
        policy_input_list: SimulationPolicyListType,
        action_names: ActionNameListType,
        permissions_boundary_policy_input_list: SimulationPolicyListType = None,
        resource_arns: ResourceNameListType = None,
        resource_policy: policyDocumentType = None,
        resource_owner: ResourceNameType = None,
        caller_arn: ResourceNameType = None,
        context_entries: ContextEntryListType = None,
        resource_handling_option: ResourceHandlingOptionType = None,
        max_items: maxItemsType = None,
        marker: markerType = None,
        **kwargs,
    ) -> SimulatePolicyResponse:
        """
        Simulate custom IAM policies.

        Note: This is a simplified stub that returns Allow for all actions.
        Full policy evaluation is not implemented.
        """
        results = []
        for action in action_names:
            result = EvaluationResult(
                EvalActionName=action,
                EvalDecision=PolicyEvaluationDecisionType.allowed,
            )
            if resource_arns:
                result["EvalResourceName"] = resource_arns[0]
            results.append(result)

        return SimulatePolicyResponse(
            EvaluationResults=results,
            IsTruncated=False,
        )

    def get_context_keys_for_custom_policy(
        self,
        context: RequestContext,
        policy_input_list: SimulationPolicyListType,
        **kwargs,
    ):
        """Get context keys required for a custom policy."""
        # Simplified stub - return empty list
        return {"ContextKeyNames": []}

    def get_context_keys_for_principal_policy(
        self,
        context: RequestContext,
        policy_source_arn: arnType,
        policy_input_list: SimulationPolicyListType = None,
        **kwargs,
    ):
        """Get context keys required for a principal policy."""
        # Simplified stub - return empty list
        return {"ContextKeyNames": []}

    # =========================================================================
    # Account Authorization Details (Native Implementation)
    # =========================================================================

    def get_account_authorization_details(
        self,
        context: RequestContext,
        filter: EntityType = None,
        max_items: maxItemsType = None,
        marker: markerType = None,
        **kwargs,
    ) -> GetAccountAuthorizationDetailsResponse:
        """Get account authorization details."""
        store = self.get_store(context.account_id, context.region)

        user_detail_list = []
        group_detail_list = []
        role_detail_list = []
        policies_list = []

        # Build user details
        for user in store.users.values():
            user_detail = UserDetail(
                UserName=user.user_name,
                UserId=user.user_id,
                Arn=user.arn,
                Path=user.path,
                CreateDate=user.create_date,
                GroupList=user.groups,
                AttachedManagedPolicies=[
                    AttachedPolicy(PolicyName=p.split("/")[-1], PolicyArn=p)
                    for p in user.attached_policies
                ],
            )
            if user.inline_policies:
                user_detail["UserPolicyList"] = [
                    PolicyDetail(PolicyName=name, PolicyDocument=doc)
                    for name, doc in user.inline_policies.items()
                ]
            if user.permission_boundary:
                user_detail["PermissionsBoundary"] = AttachedPermissionsBoundary(
                    PermissionsBoundaryArn=user.permission_boundary.permissions_boundary_arn,
                    PermissionsBoundaryType=user.permission_boundary.permissions_boundary_type,
                )
            if user.tags:
                user_detail["Tags"] = [{"Key": k, "Value": v} for k, v in user.tags.items()]
            user_detail_list.append(user_detail)

        # Build group details
        for group in store.groups.values():
            group_detail = GroupDetail(
                GroupName=group.group_name,
                GroupId=group.group_id,
                Arn=group.arn,
                Path=group.path,
                CreateDate=group.create_date,
                AttachedManagedPolicies=[
                    AttachedPolicy(PolicyName=p.split("/")[-1], PolicyArn=p)
                    for p in group.attached_policies
                ],
            )
            if group.inline_policies:
                group_detail["GroupPolicyList"] = [
                    PolicyDetail(PolicyName=name, PolicyDocument=doc)
                    for name, doc in group.inline_policies.items()
                ]
            group_detail_list.append(group_detail)

        # Build role details
        for role in store.roles.values():
            role_detail = RoleDetail(
                RoleName=role.role_name,
                RoleId=role.role_id,
                Arn=role.arn,
                Path=role.path,
                CreateDate=role.create_date,
                AssumeRolePolicyDocument=role.assume_role_policy_document,
                AttachedManagedPolicies=[
                    AttachedPolicy(PolicyName=p.split("/")[-1], PolicyArn=p)
                    for p in role.attached_policies
                ],
            )
            if role.inline_policies:
                role_detail["RolePolicyList"] = [
                    PolicyDetail(PolicyName=name, PolicyDocument=doc)
                    for name, doc in role.inline_policies.items()
                ]
            if role.permission_boundary:
                role_detail["PermissionsBoundary"] = AttachedPermissionsBoundary(
                    PermissionsBoundaryArn=role.permission_boundary.permissions_boundary_arn,
                    PermissionsBoundaryType=role.permission_boundary.permissions_boundary_type,
                )
            if role.tags:
                role_detail["Tags"] = [{"Key": k, "Value": v} for k, v in role.tags.items()]
            if role.last_used:
                role_detail["RoleLastUsed"] = RoleLastUsedType(
                    LastUsedDate=role.last_used.last_used_date,
                    Region=role.last_used.region,
                )
            role_detail_list.append(role_detail)

        # Build policy list
        for policy in store.policies.values():
            default_version = policy.get_default_version()
            policies_list.append(Policy(
                PolicyName=policy.policy_name,
                PolicyId=policy.policy_id,
                Arn=policy.arn,
                Path=policy.path,
                DefaultVersionId=policy.default_version_id,
                AttachmentCount=policy.attachment_count,
                IsAttachable=policy.is_attachable,
                CreateDate=policy.create_date,
                UpdateDate=policy.update_date,
            ))

        return GetAccountAuthorizationDetailsResponse(
            UserDetailList=user_detail_list,
            GroupDetailList=group_detail_list,
            RoleDetailList=role_detail_list,
            Policies=policies_list,
            IsTruncated=False,
        )
