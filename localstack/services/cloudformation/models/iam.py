import json
import logging
import random
import string

from botocore.exceptions import ClientError

from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import (
    PLACEHOLDER_AWS_NO_VALUE,
    dump_json_params,
    generate_default_name,
    param_defaults,
    remove_none_values,
    select_parameters,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.services.iam.provider import SERVICE_LINKED_ROLE_PATH_PREFIX
from localstack.services.lambda_.legacy.lambda_api import IAM_POLICY_VERSION
from localstack.utils.aws import arns
from localstack.utils.common import ensure_list
from localstack.utils.functions import call_safe

LOG = logging.getLogger(__name__)


class IAMManagedPolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::ManagedPolicy"

    def fetch_state(self, stack_name, resources):
        return IAMPolicy.get_policy_state(
            self.account_id, self.region_name, self, stack_name, resources, managed_policy=True
        )

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource.get("Properties", {}).get("ManagedPolicyName")
        if not role_name:
            resource["Properties"]["ManagedPolicyName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @classmethod
    def get_deploy_templates(cls):
        def _create(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            iam = connect_to(aws_access_key_id=account_id, region_name=region_name).iam
            props = resource["Properties"]

            policy_doc = json.dumps(remove_none_values(props["PolicyDocument"]))
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
            return policy

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["Policy"]["Arn"]

        return {"create": {"function": _create, "result_handler": _handle_result}}


class IAMUser(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::User"

    def fetch_state(self, stack_name, resources):
        user_name = self.props.get("UserName")
        return connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).iam.get_user(UserName=user_name)["User"]

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource["Properties"].get("UserName")
        if not role_name:
            resource["Properties"]["UserName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @staticmethod
    def get_deploy_templates():
        def _post_create(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            client = connect_to(aws_access_key_id=account_id, region_name=region_name).iam
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

        def _pre_delete(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            client = connect_to(aws_access_key_id=account_id, region_name=region_name).iam
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

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["User"]["UserName"]

        return {
            "create": [
                {
                    "function": "create_user",
                    "parameters": ["Path", "UserName", "PermissionsBoundary", "Tags"],
                    "result_handler": _handle_result,
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


class IAMAccessKey(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::AccessKey"

    def fetch_state(self, stack_name, resources):
        user_name = self.props.get("UserName")
        access_key_id = self.physical_resource_id
        if access_key_id:
            keys = connect_to(
                aws_access_key_id=self.account_id, region_name=self.region_name
            ).iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
            return [key for key in keys if key["AccessKeyId"] == access_key_id][0]

    def update_resource(self, new_resource, stack_name, resources):
        # TODO: Fix this behavior by migrating to a new resource provider
        access_key_id = self.physical_resource_id
        new_props = new_resource["Properties"]
        user_name = new_props.get("UserName")
        status = new_props.get("Status")

        connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).iam.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status=status)

    @staticmethod
    def get_deploy_templates():
        def _delete(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            iam_client = connect_to(aws_access_key_id=account_id, region_name=region_name).iam
            props = resource["Properties"]
            user_name = props["UserName"]
            access_key_id = resource["PhysicalResourceId"]

            try:
                iam_client.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
            except ClientError as err:
                if "NotSuchEntity" not in err.response["Error"]["Code"]:
                    raise

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            access_key_id = result["AccessKey"]["AccessKeyId"]
            resource["PhysicalResourceId"] = access_key_id
            resource["Properties"]["SecretAccessKey"] = result["AccessKey"]["SecretAccessKey"]
            status = resource["Properties"].get("Status", "Active")
            if status == "Inactive":
                user_name = resource["Properties"]["UserName"]
                client = connect_to(aws_access_key_id=account_id, region_name=region_name).iam
                client.update_access_key(
                    UserName=user_name, AccessKeyId=access_key_id, Status="Inactive"
                )

        return {
            "create": {
                "function": "create_access_key",
                "parameters": ["UserName"],
                "result_handler": _handle_result,
            },
            "delete": {"function": _delete},
        }


class IAMRole(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::Role"

    def fetch_state(self, stack_name, resources):
        role_name = self.props.get("RoleName")
        client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).iam
        return client.get_role(RoleName=role_name)["Role"]

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        _states = new_resource.get("_last_deployed_state", new_resource.get("_state_"))
        client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).iam
        existing_role_name = _states.get("RoleName")
        if _states:
            props_policy = props.get("AssumeRolePolicyDocument")
            # technically a change to the role name shouldn't even get here since it implies a replacement, not an in-place update
            # for now we just go with it though
            # determine if the previous name was autogenerated or not
            new_role_name = props.get("RoleName")
            name_changed = new_role_name and new_role_name != _states["RoleName"]

            # new_role_name = props.get("RoleName", _states.get("RoleName"))
            policy_changed = props_policy and props_policy != _states.get(
                "AssumeRolePolicyDocument", ""
            )
            managed_policy_arns_changed = props.get("ManagedPolicyArns", []) != _states.get(
                "ManagedPolicyArns", []
            )
            if name_changed or policy_changed or managed_policy_arns_changed:
                resource_id = new_resource.get("LogicalResourceId")
                dummy_resource = {"Properties": {"RoleName": _states.get("RoleName")}}
                IAMRole._pre_delete(
                    self.account_id, self.region_name, resource_id, dummy_resource, stack_name
                )
                client.delete_role(RoleName=_states.get("RoleName"))
                role = client.create_role(
                    RoleName=props.get("RoleName"),
                    AssumeRolePolicyDocument=json.dumps(props_policy),
                )
                IAMRole._post_create(
                    self.account_id,
                    self.region_name,
                    resource_id,
                    resources[resource_id],
                    stack_name,
                )
                return role["Role"]

        return client.update_role(
            RoleName=existing_role_name, Description=props.get("Description") or ""
        )

    @staticmethod
    def add_defaults(resource, stack_name):
        role_name = resource.get("Properties", {}).get("RoleName")
        if not role_name:
            resource["Properties"]["RoleName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @staticmethod
    def _post_create(
        account_id: str,
        region_name: str,
        logical_resource_id: str,
        resource: dict,
        stack_name: str,
    ):
        """attaches managed policies from the template to the role"""

        properties = resource["Properties"]
        iam = connect_to(aws_access_key_id=account_id, region_name=region_name).iam
        role_name = properties["RoleName"]

        # attach managed policies
        policy_arns = properties.get("ManagedPolicyArns", [])
        for arn in policy_arns:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

        # add inline policies
        inline_policies = properties.get("Policies", [])
        for policy in inline_policies:
            assert not isinstance(
                policy, list
            )  # remove if this doesn't make any problems for a while
            if policy == PLACEHOLDER_AWS_NO_VALUE:
                continue
            if not isinstance(policy, dict):
                LOG.info(
                    'Invalid format of policy for IAM role "%s": %s',
                    properties.get("RoleName"),
                    policy,
                )
                continue
            pol_name = policy.get("PolicyName")

            # get policy document - make sure we're resolving references in the policy doc
            doc = dict(policy["PolicyDocument"])
            doc = remove_none_values(doc)

            doc["Version"] = doc.get("Version") or IAM_POLICY_VERSION
            statements = ensure_list(doc["Statement"])
            for statement in statements:
                if isinstance(statement.get("Resource"), list):
                    # filter out empty resource strings
                    statement["Resource"] = [r for r in statement["Resource"] if r]
            doc = json.dumps(doc)
            iam.put_role_policy(
                RoleName=properties["RoleName"],
                PolicyName=pol_name,
                PolicyDocument=doc,
            )

    @staticmethod
    def _pre_delete(
        account_id: str, region_name: str, logical_resource_id: str, resource: dict, stack_name: str
    ):
        """detach managed policies from role before deleting"""
        iam_client = connect_to(aws_access_key_id=account_id, region_name=region_name).iam
        props = resource["Properties"]
        role_name = props["RoleName"]

        try:
            # TODO: this should probably only remove the policies that are specified in the stack (verify with AWS)
            # detach managed policies
            for policy in iam_client.list_attached_role_policies(RoleName=role_name).get(
                "AttachedPolicies", []
            ):
                call_safe(
                    iam_client.detach_role_policy,
                    kwargs={"RoleName": role_name, "PolicyArn": policy["PolicyArn"]},
                )

            # delete inline policies
            for inline_policy_name in iam_client.list_role_policies(RoleName=role_name).get(
                "PolicyNames", []
            ):
                call_safe(
                    iam_client.delete_role_policy,
                    kwargs={"RoleName": role_name, "PolicyName": inline_policy_name},
                )

            # TODO: potentially remove this when stack resource deletion order is fixed (check AWS behavior first)
            # cleanup instance profile
            rs = iam_client.list_instance_profiles_for_role(RoleName=role_name)
            for instance_profile in rs["InstanceProfiles"]:
                ip_name = instance_profile["InstanceProfileName"]
                call_safe(
                    iam_client.remove_role_from_instance_profile,
                    kwargs={"InstanceProfileName": ip_name, "RoleName": role_name},
                )
        except Exception as e:
            if "NoSuchEntity" not in str(e):
                raise

    @classmethod
    def get_deploy_templates(cls):
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["Role"]["RoleName"]
            resource["Properties"]["Arn"] = result["Role"]["Arn"]

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
                        {"RoleName": "RoleName"},
                    ),
                    "result_handler": _handle_result,
                },
                {"function": IAMRole._post_create},
            ],
            "delete": [
                {"function": IAMRole._pre_delete},
                {"function": "delete_role", "parameters": {"RoleName": "RoleName"}},
            ],
        }


class IAMServiceLinkedRole(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::ServiceLinkedRole"

    def fetch_state(self, stack_name, resources):
        iam = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).iam
        service_name = self.props["AWSServiceName"]
        path = f"{SERVICE_LINKED_ROLE_PATH_PREFIX}/{service_name}"
        roles = iam.list_roles(PathPrefix=path)["Roles"]
        for role in roles:
            policy = role.get("AssumeRolePolicyDocument") or "{}"
            policy = json.loads(policy or "{}") if isinstance(policy, str) else policy
            statements = policy.get("Statement")
            if statements and statements[0].get("Principal") == {"Service": service_name}:
                return role

    @classmethod
    def get_deploy_templates(cls):
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["Role"]["RoleName"]

        return {
            "create": {
                "function": "create_service_linked_role",
                "result_handler": _handle_result,
            },
            "delete": {"function": "delete_service_linked_role", "parameters": ["RoleName"]},
        }


class IAMPolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::Policy"

    def update_resource(self, new_resource, stack_name, resources):
        client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).iam
        props = new_resource["Properties"]
        _states = new_resource.get("_state_")
        if _states:
            policy_doc = json.dumps(remove_none_values(props["PolicyDocument"]))
            policy_name = props["PolicyName"]
            for role in props.get("Roles", []):
                client.put_role_policy(
                    RoleName=role, PolicyName=policy_name, PolicyDocument=policy_doc
                )
            for user in props.get("Users", []):
                client.put_user_policy(
                    UserName=user, PolicyName=policy_name, PolicyDocument=policy_doc
                )
            for group in props.get("Groups", []):
                client.put_group_policy(
                    GroupName=group, PolicyName=policy_name, PolicyDocument=policy_doc
                )

    def fetch_state(self, stack_name, resources):
        return IAMPolicy.get_policy_state(
            self.account_id, self.region_name, self, stack_name, resources, managed_policy=False
        )

    @classmethod
    def get_deploy_templates(cls):
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            # the physical resource ID here has a bit of a weird format
            # e.g. 'stack-fnSe-1OKWZIBB89193' where fnSe are the first 4 characters of the LogicalResourceId (or name?)
            suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=13))
            resource["PhysicalResourceId"] = f"stack-{resource.get('PolicyName', '')[:4]}-{suffix}"

        def _create(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            iam = connect_to(aws_access_key_id=account_id, region_name=region_name).iam
            props = resource["Properties"]
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

        def _delete_params(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ) -> dict:
            return {"PolicyArn": arns.policy_arn(properties["PolicyName"])}

        return {
            "create": {
                "function": _create,
                "result_handler": _handle_result,
            },
            "delete": {"function": "delete_policy", "parameters": _delete_params},
        }

    @staticmethod
    def get_policy_state(
        account_id: str, region_name: str, obj, stack_name, resources, managed_policy=False
    ):
        def _filter(pols):
            return [p for p in pols["AttachedPolicies"] if p["PolicyName"] == policy_name]

        iam = connect_to(aws_access_key_id=account_id, region_name=region_name).iam
        props = obj.props
        result = {}
        # Note: util function reused for both IAM::Policy and IAM::ManagedPolicy
        policy_name = props.get("PolicyName") or props.get("ManagedPolicyName")
        roles = props.get("Roles", [])
        users = props.get("Users", [])
        groups = props.get("Groups", [])
        if managed_policy:
            result["policy"] = iam.get_policy(PolicyArn=arns.policy_arn(policy_name))
        for role in roles:
            policies = (
                _filter(iam.list_attached_role_policies(RoleName=role))
                if managed_policy
                else iam.get_role_policy(RoleName=role, PolicyName=policy_name)
            )
            result["role:%s" % role] = policies
        for user in users:
            policies = (
                _filter(iam.list_attached_user_policies(UserName=user))
                if managed_policy
                else iam.get_user_policy(UserName=user, PolicyName=policy_name)
            )
            result["user:%s" % user] = policies
        for group in groups:
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
        instance_profile_name = self.physical_resource_id
        if not instance_profile_name:
            return None
        client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).iam
        resp = client.get_instance_profile(InstanceProfileName=instance_profile_name)
        return resp["InstanceProfile"]

    @staticmethod
    def add_defaults(resource, stack_name):
        role_name = resource.get("Properties", {}).get("InstanceProfileName")
        if not role_name:
            resource["Properties"]["InstanceProfileName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @staticmethod
    def get_deploy_templates():
        def _add_roles(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            client = connect_to(aws_access_key_id=account_id, region_name=region_name).iam
            props = resource["Properties"]
            roles = props.get("Roles")
            if roles:
                if len(roles) > 1:
                    raise Exception("Roles has too many elements. The limit is 1.")
                client.add_role_to_instance_profile(
                    InstanceProfileName=props["InstanceProfileName"],
                    RoleName=roles[0],
                )

        def _pre_delete(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            iam_client = connect_to(aws_access_key_id=account_id, region_name=region_name).iam
            props = resource["Properties"]
            roles = props.get("Roles")
            assert len(roles) == 1
            try:
                iam_client.remove_role_from_instance_profile(
                    InstanceProfileName=props["InstanceProfileName"],
                    RoleName=roles[0],
                )
            except Exception as e:
                if "NoSuchEntity" not in str(e):
                    raise

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["InstanceProfile"]["InstanceProfileName"]

        return {
            "create": [
                {
                    "function": "create_instance_profile",
                    "parameters": {
                        "InstanceProfileName": "InstanceProfileName",
                        "Path": "Path",
                    },
                    "result_handler": _handle_result,
                },
                {"function": _add_roles},
            ],
            "delete": [
                {"function": _pre_delete},
                {
                    "function": "delete_instance_profile",
                    "parameters": {"InstanceProfileName": "InstanceProfileName"},
                },
            ],
        }


class IAMGroup(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::Group"

    def fetch_state(self, stack_name, resources):
        group_name = self.props.get("GroupName")
        return connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).iam.get_group(GroupName=group_name)["Group"]

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        return connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).iam.update_group(
            GroupName=props.get("GroupName"),
            NewPath=props.get("NewPath") or "",
            NewGroupName=props.get("NewGroupName") or "",
        )

    @staticmethod
    def get_deploy_templates():
        def _post_create(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            client = connect_to(aws_access_key_id=account_id, region_name=region_name).iam
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

        def _pre_delete(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            client = connect_to(aws_access_key_id=account_id, region_name=region_name).iam
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

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["Group"]["GroupName"]

        return {
            "create": [
                {
                    "function": "create_group",
                    "parameters": ["GroupName", "Path"],
                    "result_handler": _handle_result,
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
