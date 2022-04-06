import json
import re
from copy import deepcopy
from urllib.parse import quote

from moto.iam.models import (
    AWSManagedPolicy,
    IAMNotFoundException,
    InlinePolicy,
    Policy,
    Role,
    aws_managed_policies,
    aws_managed_policies_data_parsed,
)
from moto.iam.models import iam_backend as moto_iam_backend
from moto.iam.policy_validation import VALID_STATEMENT_ELEMENTS, IAMPolicyDocumentValidator
from moto.iam.responses import GENERIC_EMPTY_TEMPLATE, LIST_ROLES_TEMPLATE, IamResponse

from localstack import config, constants
from localstack.aws.api import RequestContext
from localstack.aws.api.iam import (
    ActionNameListType,
    ContextEntryListType,
    CreateServiceLinkedRoleResponse,
    DeleteServiceLinkedRoleResponse,
    DeletionTaskIdType,
    DeletionTaskStatusType,
    EvaluationResult,
    EvaluationResultsListType,
    GetServiceLinkedRoleDeletionStatusResponse,
    IamApi,
    ListInstanceProfileTagsResponse,
    PolicyEvaluationDecisionType,
    ResourceHandlingOptionType,
    ResourceNameListType,
    ResourceNameType,
    SimulatePolicyResponse,
    SimulationPolicyListType,
    arnType,
    customSuffixType,
    groupNameType,
    instanceProfileNameType,
    markerType,
    maxItemsType,
    policyDocumentType,
    roleDescriptionType,
    roleNameType,
    tagKeyListType,
    tagListType,
)
from localstack.utils.patch import patch
from localstack.utils.strings import short_uid

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


class IamProvider(IamApi):
    def __init__(self):
        apply_patches()

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
    ) -> SimulatePolicyResponse:
        policy = moto_iam_backend.get_policy(policy_source_arn)
        policy_statements = json.loads(policy.document)["Statement"]

        evaluation_results: EvaluationResultsListType = []
        for action_name in action_names:
            for resource_arn in resource_arns:
                eval_result = EvaluationResult()
                eval_result["EvalActionName"] = action_name
                eval_result["EvalResourceName"] = resource_arn
                eval_result["EvalDecision"] = PolicyEvaluationDecisionType.explicitDeny

                def is_allow_policy_statement(policy_statement):
                    return (
                        action_name in policy_statement["Action"]
                        and resource_arn in policy_statement["Resource"]
                        and policy_statement["Effect"] == "Allow"
                    )

                #
                maybe_allow_stmt = next(filter(is_allow_policy_statement, policy_statements), None)
                if maybe_allow_stmt is not None:
                    eval_result["EvalDecision"] = PolicyEvaluationDecisionType.allowed
                    eval_result["MatchedStatements"] = []

                evaluation_results.append(eval_result)

        simulate_policy_response = SimulatePolicyResponse()
        if evaluation_results:
            simulate_policy_response["EvaluationResults"] = evaluation_results
        return simulate_policy_response

    def list_instance_profile_tags(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
    ) -> ListInstanceProfileTagsResponse:
        profile = moto_iam_backend.get_instance_profile(instance_profile_name)
        response = ListInstanceProfileTagsResponse()
        response["Tags"] = profile.tags
        return response

    def tag_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        tags: tagListType,
    ) -> None:
        profile = moto_iam_backend.get_instance_profile(instance_profile_name)
        profile.tags.update(tags)

    def untag_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        tag_keys: tagKeyListType,
    ) -> None:
        profile = moto_iam_backend.get_instance_profile(instance_profile_name)
        profile.tags = {k: v for k, v in profile.tags.items() if k not in tag_keys}

    def create_service_linked_role(
        self,
        context: RequestContext,
        aws_service_name: groupNameType,
        description: roleDescriptionType = None,
        custom_suffix: customSuffixType = None,
    ) -> CreateServiceLinkedRoleResponse:
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
        role = moto_iam_backend.create_role(
            role_name=role_name,
            assume_role_policy_document=policy_doc,
            path=path,
            permissions_boundary="",
            description=description,
            tags={},
            max_session_duration=3600,
        )
        role.service_linked_role_arn = "arn:aws:iam::{0}:role/aws-service-role/{1}/{2}".format(
            constants.TEST_AWS_ACCOUNT_ID, aws_service_name, role.name
        )
        result = CreateServiceLinkedRoleResponse()
        result["Role"] = role
        return result

    def delete_service_linked_role(
        self, context: RequestContext, role_name: roleNameType
    ) -> DeleteServiceLinkedRoleResponse:
        # TODO: consider adding bindings to deletion task ids, see get_service_linked_role_deletion_status.
        moto_iam_backend.delete_role(role_name)
        result = DeleteServiceLinkedRoleResponse()
        result["DeletionTaskId"] = short_uid()
        return result

    def get_service_linked_role_deletion_status(
        self, context: RequestContext, deletion_task_id: DeletionTaskIdType
    ) -> GetServiceLinkedRoleDeletionStatusResponse:
        # TODO: consider adding bindings to deletion task ids, see delete_service_linked_role.
        result = GetServiceLinkedRoleDeletionStatusResponse()
        result["Status"] = DeletionTaskStatusType.SUCCEEDED
        return result


def apply_patches():
    class AWSManagedPolicyUSGov(AWSManagedPolicy):
        # Fix missing regions in managed policies (e.g., aws-us-gov). Note: make sure to keep at global scope here
        # TODO: possibly find a more efficient way for this - e.g., lazy loading of policies in special regions

        @property
        def arn(self):
            return "arn:aws-us-gov:iam::aws:policy{0}{1}".format(self.path, self.name)

    # Add missing managed polices
    aws_managed_policies.extend(
        [AWSManagedPolicy.from_data(k, v) for k, v in ADDITIONAL_MANAGED_POLICIES.items()]
    )

    if "Principal" not in VALID_STATEMENT_ELEMENTS:
        VALID_STATEMENT_ELEMENTS.append("Principal")

    @patch(IAMPolicyDocumentValidator._validate_resource_syntax, pass_target=False)
    def _validate_resource_syntax(statement, *args, **kwargs):
        # Note: Serverless generates policies without "Resource" section (only "Effect"/"Principal"/"Action"),
        # which causes several policy validators in moto to fail
        if statement.get("Resource") in [None, [None]]:
            statement["Resource"] = ["*"]

    # patch get_user to include tags
    @patch(IamResponse.get_user)
    def iam_response_get_user(fn, self):
        result = fn(self)
        regex = r"(.*<UserName>\s*)([^\s]+)(\s*</UserName>.*)"
        regex2 = r"(.*<UserId>\s*)([^\s]+)(\s*</UserId>.*)"
        flags = re.MULTILINE | re.DOTALL

        user_name = re.match(regex, result, flags=flags).group(2)
        # replace default user id/name in response
        if config.TEST_IAM_USER_NAME:
            result = re.sub(regex, r"\g<1>%s\3" % config.TEST_IAM_USER_NAME, result)
            user_name = config.TEST_IAM_USER_NAME
        if config.TEST_IAM_USER_ID:
            result = re.sub(regex2, r"\g<1>%s\3" % config.TEST_IAM_USER_ID, result)

        user = moto_iam_backend.users.get(user_name)
        if not user:
            return result
        tags = moto_iam_backend.tagger.list_tags_for_resource(user.arn)
        if tags and "<Tags>" not in result:
            tags_str = "".join(
                [
                    "<member><Key>%s</Key><Value>%s</Value></member>" % (t["Key"], t["Value"])
                    for t in tags["Tags"]
                ]
            )
            result = result.replace("</Arn>", "</Arn><Tags>%s</Tags>" % tags_str)
        return result

    # patch delete_policy
    @patch(IamResponse.delete_policy, pass_target=False)
    def iam_response_delete_policy(self):
        policy_arn = self._get_param("PolicyArn")
        if moto_iam_backend.managed_policies.get(policy_arn):
            moto_iam_backend.managed_policies.pop(policy_arn, None)
            template = self.response_template(GENERIC_EMPTY_TEMPLATE)
            return template.render(name="DeletePolicy")
        else:
            raise IAMNotFoundException("Policy {0} was not found.".format(policy_arn))

    # patch detach_role_policy
    @patch(moto_iam_backend.detach_role_policy, pass_target=False)
    def iam_backend_detach_role_policy(self, policy_arn, role_name):
        try:
            role = moto_iam_backend.get_role(role_name)
            policy = role.managed_policies[policy_arn]
            policy.detach_from(role)
        except KeyError:
            raise IAMNotFoundException("Policy {0} was not found.".format(policy_arn))

    # patch policy __init__ to set document as attribute
    @patch(Policy.__init__)
    def policy__init__(
        fn, self, name, default_version_id=None, description=None, document=None, **kwargs
    ):
        fn(self, name, default_version_id, description, document, **kwargs)
        self.document = document

    # patch list_roles
    @patch(IamResponse.list_roles, pass_target=False)
    def iam_response_list_roles(self):
        roles = moto_iam_backend.get_roles()
        items = []
        for role in roles:
            item = deepcopy(role)
            item.assume_role_policy_document = quote(
                json.dumps(item.assume_role_policy_document or {})
            )
            items.append(item)

        prefix = self._get_param("PathPrefix")
        if prefix:
            filtered_roles = []
            for role in roles:
                if role.path.startswith(prefix):
                    filtered_roles.append(role)
            items = filtered_roles

        template = self.response_template(LIST_ROLES_TEMPLATE)
        return template.render(roles=items)

    # patch unapply_policy
    @patch(InlinePolicy.unapply_policy)
    def inline_policy_unapply_policy(fn, self, backend):
        try:
            fn(self, backend)
        except Exception:
            # Actually role can be deleted before policy being deleted in cloudformation
            pass

    # support for service linked roles
    @property
    def role_arn(self):
        return getattr(self, "service_linked_role_arn", None) or role_arn_orig.__get__(self)

    #
    role_arn_orig = Role.arn
    Role.arn = role_arn

    managed_policies = moto_iam_backend.managed_policies
    if "arn:aws-us-gov:iam::aws:policy/AmazonRDSFullAccess" not in managed_policies:
        for name, data in aws_managed_policies_data_parsed.items():
            policy = AWSManagedPolicyUSGov.from_data(name, data)
            if policy.arn not in moto_iam_backend.managed_policies:
                moto_iam_backend.managed_policies[policy.arn] = policy
