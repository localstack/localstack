import json
import re
from copy import deepcopy
from urllib.parse import quote

import xmltodict
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
from moto.iam.responses import (
    GENERIC_EMPTY_TEMPLATE,
    GET_ROLE_TEMPLATE,
    LIST_ROLES_TEMPLATE,
    IamResponse,
)

from localstack import config, constants
from localstack.services.infra import start_moto_server
from localstack.utils.common import short_uid

XMLNS_IAM = "https://iam.amazonaws.com/doc/2010-05-08/"

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


def apply_patches():
    # Add missing managed polices
    aws_managed_policies.extend(
        [AWSManagedPolicy.from_data(k, v) for k, v in ADDITIONAL_MANAGED_POLICIES.items()]
    )

    if "Principal" not in VALID_STATEMENT_ELEMENTS:
        VALID_STATEMENT_ELEMENTS.append("Principal")

    def _validate_resource_syntax(statement, *args, **kwargs):
        # Note: Serverless generates policies without "Resource" section (only "Effect"/"Principal"/"Action"),
        # which causes several policy validators in moto to fail
        if statement.get("Resource") in [None, [None]]:
            statement["Resource"] = ["*"]

    IAMPolicyDocumentValidator._validate_resource_syntax = _validate_resource_syntax

    def iam_response_get_user(self):
        result = iam_response_get_user_orig(self)
        user_name = re.sub(
            r".*<UserName>\s*([^\s]+)\s*</UserName>.*",
            r"\1",
            result,
            flags=re.MULTILINE | re.DOTALL,
        )
        user = moto_iam_backend.users[user_name]
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

    iam_response_get_user_orig = IamResponse.get_user
    IamResponse.get_user = iam_response_get_user

    def iam_response_delete_policy(self):
        policy_arn = self._get_param("PolicyArn")
        if moto_iam_backend.managed_policies.get(policy_arn):
            moto_iam_backend.managed_policies.pop(policy_arn, None)
            template = self.response_template(GENERIC_EMPTY_TEMPLATE)
            return template.render(name="DeletePolicy")
        else:
            raise IAMNotFoundException("Policy {0} was not found.".format(policy_arn))

    IamResponse.delete_policy = iam_response_delete_policy

    def iam_backend_detach_role_policy(policy_arn, role_name):
        try:
            role = moto_iam_backend.get_role(role_name)
            policy = role.managed_policies[policy_arn]
            policy.detach_from(role)
        except KeyError:
            raise IAMNotFoundException("Policy {0} was not found.".format(policy_arn))

    moto_iam_backend.detach_role_policy = iam_backend_detach_role_policy

    policy_init_orig = Policy.__init__

    def iam_response_simulate_principal_policy(self):
        def build_evaluation(action_name, resource_name, policy_statements):
            for statement in policy_statements:
                # TODO Implement evaluation logic here
                if (
                    action_name in statement["Action"]
                    and resource_name in statement["Resource"]
                    and statement["Effect"] == "Allow"
                ):

                    return {
                        "actionName": action_name,
                        "resourceName": resource_name,
                        "decision": "allowed",
                        "matchedStatements": [],
                    }

            return {
                "actionName": action_name,
                "resourceName": resource_name,
                "decision": "explicitDeny",
            }

        policy = moto_iam_backend.get_policy(self._get_param("PolicySourceArn"))
        policy_statements = json.loads(policy.document)["Statement"]
        actions = self._get_multi_param("ActionNames.member")
        resource_arns = self._get_multi_param("ResourceArns.member")
        evaluations = []
        for action in actions:
            for resource_arn in resource_arns:
                evaluations.append(build_evaluation(action, resource_arn, policy_statements))

        template = self.response_template(SIMULATE_PRINCIPAL_POLICY_RESPONSE)
        return template.render(evaluations=evaluations)

    def policy__init__(
        self, name, default_version_id=None, description=None, document=None, **kwargs
    ):
        policy_init_orig(self, name, default_version_id, description, document, **kwargs)
        self.document = document

    Policy.__init__ = policy__init__

    IamResponse.simulate_principal_policy = iam_response_simulate_principal_policy

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

    IamResponse.list_roles = iam_response_list_roles

    inline_policy_unapply_policy_orig = InlinePolicy.unapply_policy

    def inline_policy_unapply_policy(self, backend):
        try:
            inline_policy_unapply_policy_orig(self, backend)
        except Exception:
            # Actually role can be deleted before policy being deleted in cloudformation
            pass

    InlinePolicy.unapply_policy = inline_policy_unapply_policy

    # support update_group

    def update_group(self):
        group_name = self._get_param("GroupName")
        new_path = self._get_param("NewPath")
        new_group_name = self._get_param("NewGroupName") or group_name
        group = moto_iam_backend.get_group(group_name)
        group.path = new_path
        group.name = new_group_name
        moto_iam_backend.groups[new_group_name] = moto_iam_backend.groups.pop(group_name)
        return ""

    if not hasattr(IamResponse, "update_group"):
        IamResponse.update_group = update_group

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

    def tag_instance_profile(self):
        profile_name = self._get_param("InstanceProfileName")
        tags = self._get_multi_param("Tags.member")
        tags = {tag["Key"]: tag["Value"] for tag in tags or []}
        profile = moto_iam_backend.get_instance_profile(profile_name)
        profile.tags.update(tags)
        return ""

    if not hasattr(IamResponse, "tag_instance_profile"):
        IamResponse.tag_instance_profile = tag_instance_profile

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
            name_prefix = "service-linked-role"
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
            role = moto_iam_backend.create_role(
                role_name="%s-%s" % (name_prefix, short_uid()),
                assume_role_policy_document=policy_doc,
                path="/",
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

    # fix missing regions in managed policies (e.g., aws-us-gov)
    # TODO: possibly find a more efficient way for this - e.g., lazy loading of policies in special regions

    class AWSManagedPolicyUSGov(AWSManagedPolicy):
        @property
        def arn(self):
            return "arn:aws-us-gov:iam::aws:policy{0}{1}".format(self.path, self.name)

    managed_policies = moto_iam_backend.managed_policies
    if "arn:aws-us-gov:iam::aws:policy/AmazonRDSFullAccess" not in managed_policies:
        for name, data in aws_managed_policies_data_parsed.items():
            policy = AWSManagedPolicyUSGov.from_data(name, data)
            if policy.arn not in moto_iam_backend.managed_policies:
                moto_iam_backend.managed_policies[policy.arn] = policy


def start_iam(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_IAM

    apply_patches()
    return start_moto_server(
        "iam",
        port,
        name="IAM",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
