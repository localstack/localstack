import inspect
import json
import logging
import random
import re
import string
import uuid
from datetime import datetime
from typing import Any, Dict, List, TypeVar
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
    ActionNameListType,
    ActionNameType,
    AttachedPermissionsBoundary,
    ContextEntryListType,
    CreateRoleRequest,
    CreateRoleResponse,
    CreateServiceLinkedRoleResponse,
    CreateServiceSpecificCredentialResponse,
    CreateUserResponse,
    DeleteConflictException,
    DeleteServiceLinkedRoleResponse,
    DeletionTaskIdType,
    DeletionTaskStatusType,
    EvaluationResult,
    GetServiceLinkedRoleDeletionStatusResponse,
    GetUserResponse,
    IamApi,
    InvalidInputException,
    ListInstanceProfileTagsResponse,
    ListRolesResponse,
    ListServiceSpecificCredentialsResponse,
    MalformedPolicyDocumentException,
    NoSuchEntityException,
    PolicyEvaluationDecisionType,
    ResetServiceSpecificCredentialResponse,
    ResourceHandlingOptionType,
    ResourceNameListType,
    ResourceNameType,
    Role,
    ServiceSpecificCredential,
    ServiceSpecificCredentialMetadata,
    SimulatePolicyResponse,
    SimulationPolicyListType,
    Tag,
    User,
    arnType,
    customSuffixType,
    existingUserNameType,
    groupNameType,
    instanceProfileNameType,
    markerType,
    maxItemsType,
    pathPrefixType,
    pathType,
    policyDocumentType,
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
from localstack.constants import INTERNAL_AWS_SECRET_ACCESS_KEY
from localstack.services.iam.iam_patches import apply_iam_patches
from localstack.services.iam.resources.service_linked_roles import SERVICE_LINKED_ROLES
from localstack.services.moto import call_moto
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


def get_iam_backend(context: RequestContext) -> IAMBackend:
    return iam_backends[context.account_id][context.partition]


class IamProvider(IamApi):
    def __init__(self):
        apply_iam_patches()

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

    @staticmethod
    def build_evaluation_result(
        action_name: ActionNameType, resource_name: ResourceNameType, policy_statements: List[Dict]
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
        backend = get_iam_backend(context)
        policy = backend.get_policy(policy_source_arn)
        policy_version = backend.get_policy_version(policy_source_arn, policy.default_version_id)
        try:
            policy_statements = json.loads(policy_version.document).get("Statement", [])
        except Exception:
            raise NoSuchEntityException("Policy not found")

        evaluations = [
            self.build_evaluation_result(action_name, resource_arn, policy_statements)
            for action_name in action_names
            for resource_arn in resource_arns
        ]

        response = SimulatePolicyResponse()
        response["IsTruncated"] = False
        response["EvaluationResults"] = evaluations
        return response

    def delete_policy(self, context: RequestContext, policy_arn: arnType, **kwargs) -> None:
        backend = get_iam_backend(context)
        if backend.managed_policies.get(policy_arn):
            backend.managed_policies.pop(policy_arn, None)
        else:
            raise NoSuchEntityException("Policy {0} was not found.".format(policy_arn))

    def detach_role_policy(
        self, context: RequestContext, role_name: roleNameType, policy_arn: arnType, **kwargs
    ) -> None:
        backend = get_iam_backend(context)
        try:
            role = backend.get_role(role_name)
            policy = role.managed_policies[policy_arn]
            policy.detach_from(role)
        except KeyError:
            raise NoSuchEntityException("Policy {0} was not found.".format(policy_arn))

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
            role["Tags"] = [Tag(Key=k, Value=v) for k, v in moto_role.tags.items()]
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
            # Permission boundary should not be a part of the response
            response_role.pop("PermissionsBoundary", None)
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
        response["Tags"] = [Tag(Key=k, Value=v) for k, v in profile.tags.items()]
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
        value_by_key = {tag["Key"]: tag["Value"] for tag in tags}
        profile.tags.update(value_by_key)

    def untag_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        backend = get_iam_backend(context)
        profile = backend.get_instance_profile(instance_profile_name)
        for tag in tag_keys:
            profile.tags.pop(tag, None)

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
        self, context: RequestContext, user_name: userNameType, service_name: serviceName, **kwargs
    ) -> CreateServiceSpecificCredentialResponse:
        moto_user = self._get_user_or_raise_error(user_name, context)
        self._validate_service_name(service_name)
        credential = self._new_service_specific_credential(user_name, service_name, context)
        moto_user.service_specific_credentials.append(credential)
        return CreateServiceSpecificCredentialResponse(ServiceSpecificCredential=credential)

    def list_service_specific_credentials(
        self,
        context: RequestContext,
        user_name: userNameType = None,
        service_name: serviceName = None,
        **kwargs,
    ) -> ListServiceSpecificCredentialsResponse:
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
