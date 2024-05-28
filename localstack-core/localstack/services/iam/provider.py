import json
import re
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import quote

from moto.iam.models import (
    AccessKey,
    AWSManagedPolicy,
    IAMBackend,
    InlinePolicy,
    Policy,
    filter_items_with_path_prefix,
    iam_backends,
)
from moto.iam.models import Role as MotoRole
from moto.iam.policy_validation import VALID_STATEMENT_ELEMENTS

from localstack import config
from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.iam import (
    ActionNameListType,
    ActionNameType,
    AttachedPermissionsBoundary,
    ContextEntryListType,
    CreateRoleRequest,
    CreateRoleResponse,
    CreateServiceLinkedRoleResponse,
    CreateUserResponse,
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
    MalformedPolicyDocumentException,
    NoSuchEntityException,
    PolicyEvaluationDecisionType,
    ResourceHandlingOptionType,
    ResourceNameListType,
    ResourceNameType,
    Role,
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
    tagKeyListType,
    tagListType,
    userNameType,
)
from localstack.aws.connect import connect_to
from localstack.constants import INTERNAL_AWS_SECRET_ACCESS_KEY
from localstack.services.moto import call_moto
from localstack.utils.aws.request_context import extract_access_key_id_from_auth_header
from localstack.utils.common import short_uid
from localstack.utils.patch import patch

SERVICE_LINKED_ROLE_PATH_PREFIX = "/aws-service-role"

ADDITIONAL_MANAGED_POLICIES = {
    "AWSLambdaExecute": {
        "Arn": "arn:aws:iam::aws:policy/AWSLambdaExecute",
        "Path": "/",
        "CreateDate": "2017-10-20T17:23:10+00:00",
        "DefaultVersionId": "v4",
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["logs:*"],
                    "Resource": "arn:aws:logs:*:*:*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "arn:aws:s3:::*",
                },
            ],
        },
        "UpdateDate": "2019-05-20T18:22:18+00:00",
    }
}

POLICY_ARN_REGEX = re.compile(r"arn:[^:]+:iam::(?:\d{12}|aws):policy/.*")


def get_iam_backend(context: RequestContext) -> IAMBackend:
    return iam_backends[context.account_id]["global"]


class IamProvider(IamApi):
    def __init__(self):
        apply_patches()

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
        # TODO: test
        # TODO: how to support "CustomSuffix" API request parameter?
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
        path = f"{SERVICE_LINKED_ROLE_PATH_PREFIX}/{aws_service_name}"
        role_name = f"r-{short_uid()}"
        backend = get_iam_backend(context)
        role = backend.create_role(
            role_name=role_name,
            assume_role_policy_document=policy_doc,
            path=path,
            permissions_boundary="",
            description=description,
            tags={},
            max_session_duration=3600,
        )
        role.service_linked_role_arn = "arn:aws:iam::{0}:role/aws-service-role/{1}/{2}".format(
            context.account_id, aws_service_name, role.name
        )

        res_role = self.moto_role_to_role_type(role)
        return CreateServiceLinkedRoleResponse(Role=res_role)

    def delete_service_linked_role(
        self, context: RequestContext, role_name: roleNameType, **kwargs
    ) -> DeleteServiceLinkedRoleResponse:
        # TODO: test
        backend = get_iam_backend(context)
        backend.delete_role(role_name)
        return DeleteServiceLinkedRoleResponse(DeletionTaskId=short_uid())

    def get_service_linked_role_deletion_status(
        self, context: RequestContext, deletion_task_id: DeletionTaskIdType, **kwargs
    ) -> GetServiceLinkedRoleDeletionStatusResponse:
        # TODO: test
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

    def attach_role_policy(
        self, context: RequestContext, role_name: roleNameType, policy_arn: arnType, **kwargs
    ) -> None:
        if not POLICY_ARN_REGEX.match(policy_arn):
            raise InvalidInputException(f"ARN {policy_arn} is not valid.")
        return call_moto(context=context)

    def attach_user_policy(
        self, context: RequestContext, user_name: userNameType, policy_arn: arnType, **kwargs
    ) -> None:
        if not POLICY_ARN_REGEX.match(policy_arn):
            raise InvalidInputException(f"ARN {policy_arn} is not valid.")
        return call_moto(context=context)

    # def get_user(
    #     self, context: RequestContext, user_name: existingUserNameType = None
    # ) -> GetUserResponse:
    #     # TODO: The following migrates patch 'iam_response_get_user' as a provider function.
    #     #  However, there are concerns with utilising 'aws_stack.extract_access_key_id_from_auth_header'
    #     #  in place of 'moto.core.responses.get_current_user'.
    #     if not user_name:
    #         access_key_id = aws_stack.extract_access_key_id_from_auth_header(context.request.headers)
    #         moto_user = moto_iam_backend.get_user_from_access_key_id(access_key_id)
    #         if moto_user is None:
    #             moto_user = MotoUser("default_user")
    #     else:
    #         moto_user = moto_iam_backend.get_user(user_name)
    #
    #     response_user_name = config.TEST_IAM_USER_NAME or moto_user.name
    #     response_user_id = config.TEST_IAM_USER_ID or moto_user.id
    #     moto_user = moto_iam_backend.users.get(response_user_name) or moto_user
    #     moto_tags = moto_iam_backend.tagger.list_tags_for_resource(moto_user.arn).get("Tags", [])
    #     response_tags = None
    #     if moto_tags:
    #         response_tags = [Tag(Key=t["Key"], Value=t["Value"]) for t in moto_tags]
    #
    #     response_user = User()
    #     response_user["Path"] = moto_user.path
    #     response_user["UserName"] = response_user_name
    #     response_user["UserId"] = response_user_id
    #     response_user["Arn"] = moto_user.arn
    #     response_user["CreateDate"] = moto_user.create_date
    #     if moto_user.password_last_used:
    #         response_user["PasswordLastUsed"] = moto_user.password_last_used
    #     # response_user["PermissionsBoundary"] =   # TODO
    #     if response_tags:
    #         response_user["Tags"] = response_tags
    #     return GetUserResponse(User=response_user)


def apply_patches():
    # support service linked roles

    @property
    def moto_role_arn(self):
        return getattr(self, "service_linked_role_arn", None) or moto_role_og_arn_prop.__get__(self)

    moto_role_og_arn_prop = MotoRole.arn
    MotoRole.arn = moto_role_arn

    # Add missing managed polices
    # TODO this might not be necessary
    @patch(IAMBackend._init_aws_policies)
    def _init_aws_policies_extended(_init_aws_policies, self):
        loaded_policies = _init_aws_policies(self)
        loaded_policies.extend(
            [
                AWSManagedPolicy.from_data(name, self.account_id, self.region_name, d)
                for name, d in ADDITIONAL_MANAGED_POLICIES.items()
            ]
        )
        return loaded_policies

    if "Principal" not in VALID_STATEMENT_ELEMENTS:
        VALID_STATEMENT_ELEMENTS.append("Principal")

    # patch policy __init__ to set document as attribute

    @patch(Policy.__init__)
    def policy__init__(
        fn,
        self,
        name,
        account_id,
        region,
        default_version_id=None,
        description=None,
        document=None,
        **kwargs,
    ):
        fn(self, name, account_id, region, default_version_id, description, document, **kwargs)
        self.document = document

    # patch unapply_policy

    @patch(InlinePolicy.unapply_policy)
    def inline_policy_unapply_policy(fn, self, backend):
        try:
            fn(self, backend)
        except Exception:
            # Actually role can be deleted before policy being deleted in cloudformation
            pass

    @patch(AccessKey.__init__)
    def access_key__init__(
        fn,
        self,
        user_name: Optional[str],
        prefix: str,
        account_id: str,
        status: str = "Active",
        **kwargs,
    ):
        if not config.PARITY_AWS_ACCESS_KEY_ID:
            prefix = "L" + prefix[1:]
        fn(self, user_name, prefix, account_id, status, **kwargs)
