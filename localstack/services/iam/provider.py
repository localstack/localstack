import json
import re
from typing import Dict, List
from urllib.parse import quote

import moto.iam.models
import xmltodict
from moto.iam.models import (
    AWSManagedPolicy,
    IAMNotFoundException,
    InlinePolicy,
    Policy,
    aws_managed_policies,
    aws_managed_policies_data_parsed,
)
from moto.iam.models import iam_backend as moto_iam_backend
from moto.iam.policy_validation import VALID_STATEMENT_ELEMENTS, IAMPolicyDocumentValidator
from moto.iam.responses import GET_ROLE_TEMPLATE, IamResponse

from localstack import config, constants
from localstack.aws.api import RequestContext
from localstack.aws.api.iam import (
    ActionNameListType,
    ActionNameType,
    ContextEntryListType,
    EvaluationResult,
    IamApi,
    ListRolesResponse,
    PolicyEvaluationDecisionType,
    ResourceHandlingOptionType,
    ResourceNameListType,
    ResourceNameType,
    Role,
    SimulatePolicyResponse,
    SimulationPolicyListType,
    arnType,
    groupNameType,
    markerType,
    maxItemsType,
    pathPrefixType,
    pathType,
    policyDocumentType,
    roleNameType,
)
from localstack.utils.common import short_uid
from localstack.utils.patch import patch


class IamProvider(IamApi):
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
                eval_res["MatchedStatements"] = []  # TODO: always an empty list?
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
    ) -> SimulatePolicyResponse:
        policy = moto_iam_backend.get_policy(policy_source_arn)
        policy_version = moto_iam_backend.get_policy_version(
            policy_source_arn, policy.default_version_id
        )
        try:
            policy_statements = json.loads(policy_version.document).get("Statement", [])
        except Exception:
            raise IAMNotFoundException("Policy not found")

        evaluations = [
            self.build_evaluation_result(action_name, resource_arn, policy_statements)
            for action_name in action_names
            for resource_arn in resource_arns
        ]

        # TODO: check what else is missing from the original template (MatchedStatements, Metadata, ?)
        # TODO: originally patch returned some ResponseMetadata.RequestId constant? see:
        # <SimulatePrincipalPolicyResponse xmlns="__xmlns__">
        #   <SimulatePrincipalPolicyResult>
        #     <IsTruncated>false</IsTruncated>
        #     <EvaluationResults>
        #       {% for eval in evaluations %}
        #       <member>
        #         <MatchedStatements>
        #           <member>
        #             <SourcePolicyId>PolicyInputList.1</SourcePolicyId>
        #             <EndPosition>
        #               <Column>4</Column>
        #               <Line>7</Line>
        #             </EndPosition>
        #             <StartPosition>
        #               <Column>16</Column>
        #               <Line>3</Line>
        #             </StartPosition>
        #           </member>
        #         </MatchedStatements>
        #         <MissingContextValues/>
        #         <EvalResourceName>{{eval.resourceName}}</EvalResourceName>
        #         <EvalDecision>{{eval.decision}}</EvalDecision>
        #         <EvalActionName>{{eval.actionName}}</EvalActionName>
        #       </member>
        #       {% endfor %}
        #     </EvaluationResults>
        #   </SimulatePrincipalPolicyResult>
        #   <ResponseMetadata>
        #     <RequestId>004d7059-4c14-11e5-b121-bd8c7EXAMPLE</RequestId>
        #   </ResponseMetadata>
        # </SimulatePrincipalPolicyResponse>

        response = SimulatePolicyResponse()
        response["IsTruncated"] = False
        response["EvaluationResults"] = evaluations
        return response

    def delete_policy(self, context: RequestContext, policy_arn: arnType) -> None:
        if moto_iam_backend.managed_policies.get(policy_arn):
            moto_iam_backend.managed_policies.pop(policy_arn, None)
        else:
            raise IAMNotFoundException("Policy {0} was not found.".format(policy_arn))

    def detach_role_policy(
        self, context: RequestContext, role_name: roleNameType, policy_arn: arnType
    ) -> None:
        try:
            role = moto_iam_backend.get_role(role_name)
            policy = role.managed_policies[policy_arn]
            policy.detach_from(role)
        except KeyError:
            raise IAMNotFoundException("Policy {0} was not found.".format(policy_arn))

    @staticmethod
    def moto_role_to_role_type(moto_role: moto.iam.models.Role) -> Role:
        role = Role()
        role["Path"]: moto_role.path
        role["RoleName"]: moto_role.name
        role["RoleId"]: moto_role.id
        role["Arn"]: moto_role.arn
        role["CreateDate"]: moto_role.create_date
        role["AssumeRolePolicyDocument"]: moto_role.assume_role_policy_document
        role["Description"]: moto_role.description
        role["MaxSessionDuration"]: moto_role.max_session_duration
        role["PermissionsBoundary"]: moto_role.permissions_boundary
        role["Tags"]: moto_role.tags
        # role["RoleLastUsed"]: # TODO not supported
        return role

    def list_roles(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
    ) -> ListRolesResponse:
        moto_roles = moto_iam_backend.get_roles()

        res_roles = []
        if path_prefix:
            for moto_role in moto_roles:
                if moto_role.path.startswith(path_prefix):
                    res_roles.append(self.moto_role_to_role_type(moto_role))
        else:
            for moto_role in moto_roles:
                role = self.moto_role_to_role_type(moto_role)
                assume_role_policy_doc = role["AssumeRolePolicyDocument"]
                role["AssumeRolePolicyDocument"] = quote(json.dumps(assume_role_policy_doc or {}))
                res_roles.append(role)

        # TODO: verify what other defaults are not carried forward from original response template:
        #  <ListRolesResult>
        #     <IsTruncated>{{ 'true' if marker else 'false' }}</IsTruncated>
        #     {% if marker %}
        #     <Marker>{{ marker }}</Marker>
        #     {% endif %}
        #     <Roles>
        #       {% for role in roles %}
        #       <member>
        #         <Path>{{ role.path }}</Path>
        #         <Arn>{{ role.arn }}</Arn>
        #         <RoleName>{{ role.name }}</RoleName>
        #         <AssumeRolePolicyDocument>{{ role.assume_role_policy_document }}</AssumeRolePolicyDocument>
        #         <CreateDate>{{ role.created_iso_8601 }}</CreateDate>
        #         <RoleId>{{ role.id }}</RoleId>
        #         <MaxSessionDuration>{{ role.max_session_duration }}</MaxSessionDuration>
        #         {% if role.permissions_boundary %}
        #         <PermissionsBoundary>
        #           <PermissionsBoundaryType>PermissionsBoundaryPolicy</PermissionsBoundaryType>
        #           <PermissionsBoundaryArn>{{ role.permissions_boundary }}</PermissionsBoundaryArn>
        #         </PermissionsBoundary>
        #         {% endif %}
        #         {% if role.description is not none %}
        #         <Description>{{ role.description_escaped }}</Description>
        #         {% endif %}
        #       </member>
        #       {% endfor %}
        #     </Roles>
        #   </ListRolesResult>
        #   <ResponseMetadata>
        #     <RequestId>20f7279f-99ee-11e1-a4c3-27EXAMPLE804</RequestId>
        #   </ResponseMetadata>
        # </ListRolesResponse>

        response = ListRolesResponse()
        response["Roles"] = res_roles
        response["IsTruncated"] = False
        return response

    def update_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        new_path: pathType = None,
        new_group_name: groupNameType = None,
    ) -> None:
        new_group_name = new_group_name or group_name
        group = moto_iam_backend.get_group(group_name)
        group.path = new_path
        group.name = new_group_name
        moto_iam_backend.groups[new_group_name] = moto_iam_backend.groups.pop(group_name)

    # TODO: tag patches seem outdated?
    # def list_instance_profile_tags(
    #     self,
    #     context: RequestContext,
    #     instance_profile_name: instanceProfileNameType,
    #     marker: markerType = None,
    #     max_items: maxItemsType = None,
    # ) -> ListInstanceProfileTagsResponse:
    #     # TODO: test
    #     profile = moto_iam_backend.get_instance_profile(instance_profile_name)
    #     # result = {
    #     #     "ListInstanceProfileTagsResponse": {
    #     #         "@xmlns": XMLNS_IAM,
    #     #         "ListInstanceProfileTagsResult": {"Tags": profile.tags},
    #     #     }
    #     # }
    #     tags = []
    #     for role in profile["roles"]:
    #         for k, v in role
    #         tags.append(Tag(Key=))
    #     response = ListInstanceProfileTagsResponse()
    #     response["Tags"] = [Tag(k, v) for k, v in profile.tags.items()]
    #     return response


# TODO: complete migrating patches below into asf provider.

XMLNS_IAM = "https://iam.amazonaws.com/doc/2010-05-08/"

SERVICE_LINKED_ROLE_PATH_PREFIX = "/aws-service-role"

USER_RESPONSE_TEMPLATE = """<{{ action }}UserResponse>
   <{{ action }}UserResult>
      <User>
         <Path>{{ user.path }}</Path>
         <UserName>{{ user.name }}</UserName>
         <UserId>{{ user.id }}</UserId>
         <Arn>{{ user.arn }}</Arn>
         <CreateDate>{{ user.created_iso_8601 }}</CreateDate>
         <Tags>
            {% for tag in user.tags %}<member>
                <Key>{{ tag.Key }}</Key>
                <Value>{{ tag.Value }}</Value>
            </member>{% endfor %}
         </Tags>
     </User>
   </{{ action }}UserResult>
   <ResponseMetadata>
      <RequestId>{{request_id}}</RequestId>
   </ResponseMetadata>
</{{ action }}UserResponse>"""

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

SIMULATE_PRINCIPAL_POLICY_RESPONSE = """
<SimulatePrincipalPolicyResponse xmlns="__xmlns__">
  <SimulatePrincipalPolicyResult>
    <IsTruncated>false</IsTruncated>
    <EvaluationResults>
      {% for eval in evaluations %}
      <member>
        <MatchedStatements>
          <member>
            <SourcePolicyId>PolicyInputList.1</SourcePolicyId>
            <EndPosition>
              <Column>4</Column>
              <Line>7</Line>
            </EndPosition>
            <StartPosition>
              <Column>16</Column>
              <Line>3</Line>
            </StartPosition>
          </member>
        </MatchedStatements>
        <MissingContextValues/>
        <EvalResourceName>{{eval.resourceName}}</EvalResourceName>
        <EvalDecision>{{eval.decision}}</EvalDecision>
        <EvalActionName>{{eval.actionName}}</EvalActionName>
      </member>
      {% endfor %}
    </EvaluationResults>
  </SimulatePrincipalPolicyResult>
  <ResponseMetadata>
    <RequestId>004d7059-4c14-11e5-b121-bd8c7EXAMPLE</RequestId>
  </ResponseMetadata>
</SimulatePrincipalPolicyResponse>""".replace(
    "__xmlns__", XMLNS_IAM
)


class AWSManagedPolicyUSGov(AWSManagedPolicy):
    # Fix missing regions in managed policies (e.g., aws-us-gov). Note: make sure to keep at global scope here
    # TODO: possibly find a more efficient way for this - e.g., lazy loading of policies in special regions

    @property
    def arn(self):
        return "arn:aws-us-gov:iam::aws:policy{0}{1}".format(self.path, self.name)


def apply_patches():
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

    # patch policy __init__ to set document as attribute

    @patch(Policy.__init__)
    def policy__init__(
        fn, self, name, default_version_id=None, description=None, document=None, **kwargs
    ):
        fn(self, name, default_version_id, description, document, **kwargs)
        self.document = document

    # patch unapply_policy

    @patch(InlinePolicy.unapply_policy)
    def inline_policy_unapply_policy(fn, self, backend):
        try:
            fn(self, backend)
        except Exception:
            # Actually role can be deleted before policy being deleted in cloudformation
            pass

    # support instance profile tags

    def list_instance_profile_tags(self):
        profile_name = self._get_param("InstanceProfileName")
        profile = moto_iam_backend.get_instance_profile(profile_name)
        result = {
            "ListInstanceProfileTagsResponse": {
                "@xmlns": XMLNS_IAM,
                "ListInstanceProfileTagsResult": {"Tags": profile.tags},
            }
        }
        return xmltodict.unparse(result)

    if not hasattr(IamResponse, "list_instance_profile_tags"):
        IamResponse.list_instance_profile_tags = list_instance_profile_tags

    # patch/implement tag_instance_profile

    def tag_instance_profile(self):
        profile_name = self._get_param("InstanceProfileName")
        tags = self._get_multi_param("Tags.member")
        tags = {tag["Key"]: tag["Value"] for tag in tags or []}
        profile = moto_iam_backend.get_instance_profile(profile_name)
        profile.tags.update(tags)
        return ""

    if not hasattr(IamResponse, "tag_instance_profile"):
        IamResponse.tag_instance_profile = tag_instance_profile

    # patch/implement untag_instance_profile

    def untag_instance_profile(self):
        profile_name = self._get_param("InstanceProfileName")
        tag_keys = self._get_multi_param("TagKeys.member")
        profile = moto_iam_backend.get_instance_profile(profile_name)
        profile.tags = {k: v for k, v in profile.tags.items() if k not in tag_keys}
        return ""

    if not hasattr(IamResponse, "untag_instance_profile"):
        IamResponse.untag_instance_profile = untag_instance_profile

    # support policy tags

    def tag_policy(self):
        policy_arn = self._get_param("PolicyArn")
        tags = self._get_multi_param("Tags.member")
        tags = {tag["Key"]: tag["Value"] for tag in tags or []}
        policy = moto_iam_backend.get_policy(policy_arn)
        policy.tags.update(tags)
        return ""

    if not hasattr(IamResponse, "tag_policy"):
        IamResponse.tag_policy = tag_policy

    def untag_policy(self):
        policy_arn = self._get_param("PolicyArn")
        tag_keys = self._get_multi_param("TagKeys.member")
        policy = moto_iam_backend.get_policy(policy_arn)
        policy.tags = {k: v for k, v in policy.tags.items() if k not in tag_keys}
        return ""

    if not hasattr(IamResponse, "untag_policy"):
        IamResponse.untag_policy = untag_policy

    # support service linked roles

    if not hasattr(IamResponse, "create_service_linked_role"):

        @property
        def role_arn(self):
            return getattr(self, "service_linked_role_arn", None) or role_arn_orig.__get__(self)

        role_arn_orig = Role.arn
        Role.arn = role_arn

        def create_service_linked_role(self):
            service_name = self._get_param("AWSServiceName")
            description = self._get_param("Description")
            # TODO: how to support "CustomSuffix" API request parameter?
            policy_doc = json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": service_name},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            )
            path = f"{SERVICE_LINKED_ROLE_PATH_PREFIX}/{service_name}"
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
            template = self.response_template(GET_ROLE_TEMPLATE)
            role.service_linked_role_arn = "arn:aws:iam::{0}:role/aws-service-role/{1}/{2}".format(
                constants.TEST_AWS_ACCOUNT_ID, service_name, role.name
            )
            result = re.sub(
                r"<(/)?GetRole",
                r"<\1CreateServiceLinkedRole",
                template.render(role=role),
            )
            return result

        IamResponse.create_service_linked_role = create_service_linked_role

    if not hasattr(IamResponse, "delete_service_linked_role"):

        def delete_service_linked_role(self):
            role_name = self._get_param("RoleName")
            moto_iam_backend.delete_role(role_name)
            result = {
                "DeleteServiceLinkedRoleResponse": {
                    "@xmlns": XMLNS_IAM,
                    "DeleteServiceLinkedRoleResult": {"DeletionTaskId": short_uid()},
                }
            }
            return xmltodict.unparse(result)

        IamResponse.delete_service_linked_role = delete_service_linked_role

    if not hasattr(IamResponse, "get_service_linked_role_deletion_status"):

        def get_service_linked_role_deletion_status(self):
            result = {
                "GetServiceLinkedRoleDeletionStatusResponse": {
                    "@xmlns": XMLNS_IAM,
                    "GetServiceLinkedRoleDeletionStatusResult": {"Status": "SUCCEEDED"},
                }
            }
            return xmltodict.unparse(result)

        IamResponse.get_service_linked_role_deletion_status = (
            get_service_linked_role_deletion_status
        )

    managed_policies = moto_iam_backend.managed_policies
    if "arn:aws-us-gov:iam::aws:policy/AmazonRDSFullAccess" not in managed_policies:
        for name, data in aws_managed_policies_data_parsed.items():
            policy = AWSManagedPolicyUSGov.from_data(name, data)
            if policy.arn not in moto_iam_backend.managed_policies:
                moto_iam_backend.managed_policies[policy.arn] = policy
