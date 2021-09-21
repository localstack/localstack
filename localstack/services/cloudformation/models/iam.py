import json
import logging

from moto.iam.models import Role as MotoRole

from localstack.services.awslambda.lambda_api import IAM_POLICY_VERSION
from localstack.services.cloudformation.deployment_utils import (
    PLACEHOLDER_AWS_NO_VALUE,
    PLACEHOLDER_RESOURCE_NAME,
    dump_json_params,
    param_defaults,
    remove_none_values,
    select_parameters,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack
from localstack.utils.common import ensure_list

LOG = logging.getLogger(__name__)


class IAMManagedPolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::ManagedPolicy"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return aws_stack.policy_arn(self.props["ManagedPolicyName"])

    def fetch_state(self, stack_name, resources):
        return IAMPolicy.get_policy_state(self, stack_name, resources, managed_policy=True)

    @classmethod
    def get_deploy_templates(cls):
        def _create(resource_id, resources, resource_type, func, stack_name, *args, **kwargs):
            iam = aws_stack.connect_to_service("iam")
            resource = resources[resource_id]
            props = resource["Properties"]
            cls.resolve_refs_recursively(stack_name, props, resources)
            policy_doc = json.dumps(props["PolicyDocument"])
            policy = iam.create_policy(
                PolicyName=props["ManagedPolicyName"], PolicyDocument=policy_doc
            )
            policy_arn = policy["Policy"]["Arn"]
            for role in resource.get("Roles", []):
                iam.attach_role_policy(RoleName=role, PolicyArn=policy_arn)
            for user in resource.get("Users", []):
                iam.attach_user_policy(UserName=user, PolicyArn=policy_arn)
            for group in resource.get("Groups", []):
                iam.attach_group_policy(GroupName=group, PolicyArn=policy_arn)
            return {}

        return {"create": {"function": _create}}


class IAMUser(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::User"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("UserName")

    def get_resource_name(self):
        return self.props.get("UserName")

    def fetch_state(self, stack_name, resources):
        user_name = self.resolve_refs_recursively(stack_name, self.props.get("UserName"), resources)
        return aws_stack.connect_to_service("iam").get_user(UserName=user_name)["User"]

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        client = aws_stack.connect_to_service("iam")
        return client.update_user(
            UserName=props.get("UserName"),
            NewPath=props.get("NewPath") or "",
            NewUserName=props.get("NewUserName") or "",
        )

    @staticmethod
    def get_deploy_templates():
        def _post_create(resource_id, resources, resource_type, func, stack_name):
            client = aws_stack.connect_to_service("iam")
            resource = resources[resource_id]
            props = resource["Properties"]
            username = props["UserName"]

            for group in props.get("Groups", []):
                client.add_user_to_group(UserName=username, GroupName=group)
            for managed_policy in props.get("ManagedPolicyArns", []):
                client.attach_user_policy(UserName=username, PolicyArn=managed_policy)
            for policy in props.get("Policies", []):
                policy_doc = json.dumps(policy.get("PolicyDocument"))
                client.put_user_policy(
                    UserName=username,
                    PolicyName=policy.get("PolicyName"),
                    PolicyDocument=policy_doc,
                )
            login_profile = props.get("LoginProfile")
            if login_profile:
                client.create_login_profile(
                    UserName=username,
                    Password=login_profile.get("Password"),
                    PasswordResetRequired=login_profile.get("PasswordResetRequired"),
                )

        def _pre_delete(resource_id, resources, resource_type, func, stack_name):
            client = aws_stack.connect_to_service("iam")
            resource = resources[resource_id]
            props = resource["Properties"]
            user_name = props["UserName"]

            for managed_policy in props.get("ManagedPolicyArns", []):
                client.detach_user_policy(UserName=user_name, PolicyArn=managed_policy)

            for inline_policy in props.get("Policies", []):
                client.delete_user_policy(
                    UserName=user_name, PolicyName=inline_policy.get("PolicyName")
                )

            if props.get("LoginProfile"):
                client.delete_login_profile(UserName=user_name)

            for group in props.get("Groups", []):
                client.remove_user_from_group(UserName=user_name, GroupName=group)

            # TODO: remove this after stack resource deletion order is fixed
            remaining_policies = client.list_user_policies(UserName=user_name)["PolicyNames"]
            for inline_policy_name in remaining_policies:
                client.delete_user_policy(UserName=user_name, PolicyName=inline_policy_name)

        return {
            "create": [
                {
                    "function": "create_user",
                    "parameters": ["Path", "UserName", "PermissionsBoundary", "Tags"],
                },
                {"function": _post_create},
            ],
            "delete": [
                {"function": _pre_delete},
                {
                    "function": "delete_user",
                    "parameters": ["UserName"],
                },
            ],
        }


class IAMRole(GenericBaseModel, MotoRole):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::Role"

    def get_resource_name(self):
        return self.props.get("RoleName")

    def fetch_state(self, stack_name, resources):
        role_name = self.resolve_refs_recursively(stack_name, self.props.get("RoleName"), resources)
        return aws_stack.connect_to_service("iam").get_role(RoleName=role_name)["Role"]

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        client = aws_stack.connect_to_service("iam")
        return client.update_role(
            RoleName=props.get("RoleName"), Description=props.get("Description") or ""
        )

    @classmethod
    def get_deploy_templates(cls):
        def _post_create(resource_id, resources, resource_type, func, stack_name):
            """attaches managed policies from the template to the role"""
            iam = aws_stack.connect_to_service("iam")
            resource = resources[resource_id]
            props = resource["Properties"]
            role_name = props["RoleName"]

            # attach managed policies
            policy_arns = props.get("ManagedPolicyArns", [])
            for arn in policy_arns:
                iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

            # add inline policies
            inline_policies = props.get("Policies", [])
            for policy in inline_policies:
                assert not isinstance(
                    policy, list
                )  # remove if this doesn't make any problems for a while
                if policy == PLACEHOLDER_AWS_NO_VALUE:
                    continue
                if not isinstance(policy, dict):
                    LOG.info(
                        'Invalid format of policy for IAM role "%s": %s'
                        % (props.get("RoleName"), policy)
                    )
                    continue
                pol_name = policy.get("PolicyName")
                doc = dict(policy["PolicyDocument"])
                doc["Version"] = doc.get("Version") or IAM_POLICY_VERSION
                statements = ensure_list(doc["Statement"])
                for statement in statements:
                    if isinstance(statement.get("Resource"), list):
                        # filter out empty resource strings
                        statement["Resource"] = [r for r in statement["Resource"] if r]
                doc = json.dumps(doc)
                iam.put_role_policy(
                    RoleName=props["RoleName"],
                    PolicyName=pol_name,
                    PolicyDocument=doc,
                )

        def _pre_delete(resource_id, resources, resource_type, func, stack_name):
            """detach managed policies from role before deleting"""
            iam = aws_stack.connect_to_service("iam")
            resource = resources[resource_id]
            props = resource["Properties"]
            role_name = props["RoleName"]

            # TODO: this should probably only remove the policies that are specified in the stack (verify with AWS)
            # detach managed policies
            for policy in iam.list_attached_role_policies(RoleName=role_name).get(
                "AttachedPolicies", []
            ):
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy["PolicyArn"])
            # delete inline policies
            for inline_policy_name in iam.list_role_policies(RoleName=role_name).get(
                "PolicyNames", []
            ):
                iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name)

        return {
            "create": [
                {
                    "function": "create_role",
                    "parameters": param_defaults(
                        dump_json_params(
                            select_parameters(
                                "Path",
                                "RoleName",
                                "AssumeRolePolicyDocument",
                                "Description",
                                "MaxSessionDuration",
                                "PermissionsBoundary",
                                "Tags",
                            ),
                            "AssumeRolePolicyDocument",
                        ),
                        {"RoleName": PLACEHOLDER_RESOURCE_NAME},
                    ),
                },
                {"function": _post_create},
            ],
            "delete": [
                {"function": _pre_delete},
                {"function": "delete_role", "parameters": {"RoleName": "RoleName"}},
            ],
        }


class IAMPolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::Policy"

    def fetch_state(self, stack_name, resources):
        return IAMPolicy.get_policy_state(self, stack_name, resources, managed_policy=False)

    @classmethod
    def get_deploy_templates(cls):
        def _create(resource_id, resources, resource_type, func, stack_name, *args, **kwargs):
            iam = aws_stack.connect_to_service("iam")
            props = resources[resource_id]["Properties"]
            cls.resolve_refs_recursively(stack_name, props, resources)
            policy_doc = json.dumps(remove_none_values(props["PolicyDocument"]))
            policy_name = props["PolicyName"]
            for role in props.get("Roles", []):
                iam.put_role_policy(
                    RoleName=role, PolicyName=policy_name, PolicyDocument=policy_doc
                )
            for user in props.get("Users", []):
                iam.put_user_policy(
                    UserName=user, PolicyName=policy_name, PolicyDocument=policy_doc
                )
            for group in props.get("Groups", []):
                iam.put_group_policy(
                    GroupName=group, PolicyName=policy_name, PolicyDocument=policy_doc
                )

        return {"create": {"function": _create}}

    @staticmethod
    def get_policy_state(obj, stack_name, resources, managed_policy=False):
        def _filter(pols):
            return [p for p in pols["AttachedPolicies"] if p["PolicyName"] == policy_name]

        iam = aws_stack.connect_to_service("iam")
        props = obj.props
        policy_name = props.get("PolicyName") or props.get("ManagedPolicyName")
        result = {}
        roles = props.get("Roles", [])
        users = props.get("Users", [])
        groups = props.get("Groups", [])
        if managed_policy:
            result["policy"] = iam.get_policy(PolicyArn=aws_stack.policy_arn(policy_name))
        for role in roles:
            role = obj.resolve_refs_recursively(stack_name, role, resources)
            policies = (
                _filter(iam.list_attached_role_policies(RoleName=role))
                if managed_policy
                else iam.get_role_policy(RoleName=role, PolicyName=policy_name)
            )
            result["role:%s" % role] = policies
        for user in users:
            user = obj.resolve_refs_recursively(stack_name, user, resources)
            policies = (
                _filter(iam.list_attached_user_policies(UserName=user))
                if managed_policy
                else iam.get_user_policy(UserName=user, PolicyName=policy_name)
            )
            result["user:%s" % user] = policies
        for group in groups:
            group = obj.resolve_refs_recursively(stack_name, group, resources)
            policies = (
                _filter(iam.list_attached_group_policies(GroupName=group))
                if managed_policy
                else iam.get_group_policy(GroupName=group, PolicyName=policy_name)
            )
            result["group:%s" % group] = policies
        result = {k: v for k, v in result.items() if v}
        return result or None


class InstanceProfile(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::InstanceProfile"

    def fetch_state(self, stack_name, resources):
        instance_profile_name = self.get_physical_resource_id()
        if not instance_profile_name:
            return None
        client = aws_stack.connect_to_service("iam")
        resp = client.get_instance_profile(InstanceProfileName=instance_profile_name)
        return resp["InstanceProfile"]

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.physical_resource_id or self.props.get("InstanceProfileName")

    @staticmethod
    def get_deploy_templates():
        def _add_roles(resource_id, resources, resource_type, func, stack_name):
            client = aws_stack.connect_to_service("iam")
            resource = resources[resource_id]
            props = resource["Properties"]
            roles = props.get("Roles")
            if roles:
                if len(roles) > 1:
                    raise Exception("Roles has too many elements. The limit is 1.")
                client.add_role_to_instance_profile(
                    InstanceProfileName=props["InstanceProfileName"],
                    RoleName=roles[0],
                )

        return {
            "create": [
                {
                    "function": "create_instance_profile",
                    "parameters": {
                        "InstanceProfileName": "InstanceProfileName",
                        "Path": "Path",
                    },
                },
                {"function": _add_roles},
            ],
            "delete": {
                "function": "delete_instance_profile",
                "parameters": {"InstanceProfileName": "InstanceProfileName"},
            },
        }


class IAMGroup(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::Group"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("GroupName")

    def get_resource_name(self):
        return self.props.get("GroupName")

    def fetch_state(self, stack_name, resources):
        group_name = self.resolve_refs_recursively(
            stack_name, self.props.get("GroupName"), resources
        )
        return aws_stack.connect_to_service("iam").get_group(GroupName=group_name)["Group"]

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        return aws_stack.connect_to_service("iam").update_group(
            GroupName=props.get("GroupName"),
            NewPath=props.get("NewPath") or "",
            NewGroupName=props.get("NewGroupName") or "",
        )

    @staticmethod
    def get_deploy_templates():
        def _post_create(resource_id, resources, resource_type, func, stack_name):
            client = aws_stack.connect_to_service("iam")
            resource = resources[resource_id]
            props = resource["Properties"]
            group_name = props["GroupName"]

            for managed_policy in props.get("ManagedPolicyArns", []):
                client.attach_group_policy(GroupName=group_name, PolicyArn=managed_policy)

            for inline_policy in props.get("Policies", []):
                doc = json.dumps(inline_policy.get("PolicyDocument"))
                client.put_group_policy(
                    GroupName=group_name,
                    PolicyName=inline_policy.get("PolicyName"),
                    PolicyDocument=doc,
                )

        def _pre_delete(resource_id, resources, resource_type, func, stack_name):
            client = aws_stack.connect_to_service("iam")
            resource = resources[resource_id]
            props = resource["Properties"]
            group_name = props["GroupName"]

            for managed_policy in props.get("ManagedPolicyArns", []):
                client.detach_group_policy(GroupName=group_name, PolicyArn=managed_policy)

            for inline_policy in props.get("Policies", []):
                client.delete_group_policy(
                    GroupName=group_name, PolicyName=inline_policy.get("PolicyName")
                )

            # TODO: remove this after stack resource deletion order is fixed
            remaining_policies = client.list_group_policies(GroupName=group_name)["PolicyNames"]
            for inline_policy_name in remaining_policies:
                client.delete_group_policy(GroupName=group_name, PolicyName=inline_policy_name)

        return {
            "create": [
                {
                    "function": "create_group",
                    "parameters": ["GroupName", "Path"],
                },
                {"function": _post_create},
            ],
            "delete": [
                {"function": _pre_delete},
                {
                    "function": "delete_group",
                    "parameters": ["GroupName"],
                },
            ],
        }
