import json

from moto.iam.models import Role as MotoRole

from localstack.services.cloudformation.deployment_utils import remove_none_values
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack


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
        return {
            "create": {
                "function": "create_user",
                "parameters": ["Path", "UserName", "PermissionsBoundary", "Tags"],
            },
            "delete": {
                "function": "delete_user",
                "parameters": ["UserName"],
            },
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
            return {}

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
        return {
            "create": {
                "function": "create_instance_profile",
                "parameters": {
                    "InstanceProfileName": "InstanceProfileName",
                    "Path": "Path",
                },
            },
            "delete": {
                "function": "delete_instance_profile",
                "parameters": {"InstanceProfileName": "InstanceProfileName"},
            },
        }
