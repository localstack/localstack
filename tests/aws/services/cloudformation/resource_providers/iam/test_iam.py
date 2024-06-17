import json
import os

import pytest

from localstack.services.iam.provider import SERVICE_LINKED_ROLE_PATH_PREFIX
from localstack.testing.pytest import markers
from localstack.utils.common import short_uid


@markers.aws.validated
def test_delete_role_detaches_role_policy(deploy_cfn_template, aws_client):
    role_name = f"LsRole{short_uid()}"
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../../templates/iam_role_policy.yaml"
        ),
        parameters={"RoleName": role_name},
    )
    attached_policies = aws_client.iam.list_attached_role_policies(RoleName=role_name)[
        "AttachedPolicies"
    ]
    assert len(attached_policies) > 0

    deploy_cfn_template(
        is_update=True,
        stack_name=stack.stack_name,
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../../templates/iam_role_policy.yaml"
        ),
        parameters={"RoleName": f"role-{short_uid()}"},
    )

    with pytest.raises(Exception) as e:
        aws_client.iam.list_attached_role_policies(RoleName=role_name)
    assert e.value.response.get("Error").get("Code") == "NoSuchEntity"


@markers.aws.validated
def test_policy_attachments(deploy_cfn_template, aws_client):
    role_name = f"role-{short_uid()}"
    group_name = f"group-{short_uid()}"
    user_name = f"user-{short_uid()}"
    policy_name = f"policy-{short_uid()}"

    linked_role_id = short_uid()
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../../templates/iam_policy_attachments.yaml"
        ),
        template_mapping={
            "role_name": role_name,
            "policy_name": policy_name,
            "user_name": user_name,
            "group_name": group_name,
            "service_linked_role_id": linked_role_id,
        },
    )

    # check inline policies
    role_inline_policies = aws_client.iam.list_role_policies(RoleName=role_name)
    user_inline_policies = aws_client.iam.list_user_policies(UserName=user_name)
    group_inline_policies = aws_client.iam.list_group_policies(GroupName=group_name)
    assert len(role_inline_policies["PolicyNames"]) == 2
    assert len(user_inline_policies["PolicyNames"]) == 1
    assert len(group_inline_policies["PolicyNames"]) == 1

    # check managed/attached policies
    role_attached_policies = aws_client.iam.list_attached_role_policies(RoleName=role_name)
    user_attached_policies = aws_client.iam.list_attached_user_policies(UserName=user_name)
    group_attached_policies = aws_client.iam.list_attached_group_policies(GroupName=group_name)
    assert len(role_attached_policies["AttachedPolicies"]) == 1
    assert len(user_attached_policies["AttachedPolicies"]) == 1
    assert len(group_attached_policies["AttachedPolicies"]) == 1

    # check service linked roles
    roles = aws_client.iam.list_roles(PathPrefix=SERVICE_LINKED_ROLE_PATH_PREFIX)["Roles"]
    matching = [r for r in roles if r.get("Description") == f"service linked role {linked_role_id}"]
    assert matching
    policy = matching[0]["AssumeRolePolicyDocument"]
    policy = json.loads(policy) if isinstance(policy, str) else policy
    assert policy["Statement"][0]["Principal"] == {"Service": "elasticbeanstalk.amazonaws.com"}


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..User.Tags"])
def test_iam_username_defaultname(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.iam_api())
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    template = json.dumps(
        {
            "Resources": {
                "DefaultNameUser": {
                    "Type": "AWS::IAM::User",
                }
            },
            "Outputs": {"DefaultNameUserOutput": {"Value": {"Ref": "DefaultNameUser"}}},
        }
    )
    stack = deploy_cfn_template(template=template)
    user_name = stack.outputs["DefaultNameUserOutput"]
    assert user_name

    get_iam_user = aws_client.iam.get_user(UserName=user_name)
    snapshot.match("get_iam_user", get_iam_user)


@markers.aws.validated
def test_iam_user_access_key(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("AccessKeyId", "key-id"),
            snapshot.transform.key_value("UserName", "user-name"),
            snapshot.transform.key_value("SecretAccessKey", "secret-access-key"),
        ]
    )

    user_name = f"user-{short_uid()}"
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../../templates/iam_access_key.yaml"
        ),
        parameters={"UserName": user_name},
    )

    snapshot.match("key_outputs", stack.outputs)
    key = aws_client.iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"][0]
    snapshot.match("access_key", key)

    # Update Status
    stack2 = deploy_cfn_template(
        stack_name=stack.stack_name,
        is_update=True,
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../../templates/iam_access_key.yaml"
        ),
        parameters={"UserName": user_name, "Status": "Inactive", "Serial": "2"},
    )
    keys = aws_client.iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    updated_key = [k for k in keys if k["AccessKeyId"] == stack2.outputs["AccessKeyId"]][0]
    # IAM just being IAM. First key takes a bit to delete and in the meantime might still be visible here
    snapshot.match("access_key_updated", updated_key)
    assert stack2.outputs["AccessKeyId"] != stack.outputs["AccessKeyId"]
    assert stack2.outputs["SecretAccessKey"] != stack.outputs["SecretAccessKey"]


@markers.aws.validated
def test_update_inline_policy(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.iam_api())
    snapshot.add_transformer(snapshot.transform.key_value("PolicyName", "policy-name"))
    snapshot.add_transformer(snapshot.transform.key_value("RoleName", "role-name"))
    snapshot.add_transformer(snapshot.transform.key_value("UserName", "user-name"))

    policy_name = f"policy-{short_uid()}"
    user_name = f"user-{short_uid()}"
    role_name = f"role-{short_uid()}"

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../../templates/iam_policy_role.yaml"
        ),
        parameters={
            "PolicyName": policy_name,
            "UserName": user_name,
            "RoleName": role_name,
        },
    )

    user_inline_policy_response = aws_client.iam.get_user_policy(
        UserName=user_name, PolicyName=policy_name
    )
    role_inline_policy_resource = aws_client.iam.get_role_policy(
        RoleName=role_name, PolicyName=policy_name
    )

    snapshot.match("user_inline_policy", user_inline_policy_response)
    snapshot.match("role_inline_policy", role_inline_policy_resource)

    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../../templates/iam_policy_role_updated.yaml"
        ),
        parameters={
            "PolicyName": policy_name,
            "UserName": user_name,
            "RoleName": role_name,
        },
        stack_name=stack.stack_name,
        is_update=True,
    )

    user_updated_inline_policy_response = aws_client.iam.get_user_policy(
        UserName=user_name, PolicyName=policy_name
    )
    role_updated_inline_policy_resource = aws_client.iam.get_role_policy(
        RoleName=role_name, PolicyName=policy_name
    )

    snapshot.match("user_updated_inline_policy", user_updated_inline_policy_response)
    snapshot.match("role_updated_inline_policy", role_updated_inline_policy_resource)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..Policy.Description",
        "$..Policy.IsAttachable",
        "$..Policy.PermissionsBoundaryUsageCount",
        "$..Policy.Tags",
    ]
)
def test_managed_policy_with_empty_resource(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(
        snapshot.transform.iam_api(),
    )
    snapshot.add_transformers_list(
        [snapshot.transform.resource_name(), snapshot.transform.key_value("PolicyId", "policy-id")]
    )

    parameters = {
        "tableName": f"table-{short_uid()}",
        "policyName": f"managed-policy-{short_uid()}",
    }

    template_path = os.path.join(
        os.path.dirname(__file__), "../../../../templates/dynamodb_iam.yaml"
    )

    stack = deploy_cfn_template(template_path=template_path, parameters=parameters)

    snapshot.match("outputs", stack.outputs)

    policy_arn = stack.outputs["PolicyArn"]
    policy = aws_client.iam.get_policy(PolicyArn=policy_arn)
    snapshot.match("managed_policy", policy)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..ServerCertificate.Tags",
    ]
)
def test_server_certificate(deploy_cfn_template, snapshot, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../../templates/iam_server_certificate.yaml"
        ),
        parameters={"certificateName": f"server-certificate-{short_uid()}"},
    )
    snapshot.match("outputs", stack.outputs)

    certificate = aws_client.iam.get_server_certificate(
        ServerCertificateName=stack.outputs["ServerCertificateName"]
    )
    snapshot.match("certificate", certificate)

    stack.destroy()
    with pytest.raises(Exception) as e:
        aws_client.iam.get_server_certificate(
            ServerCertificateName=stack.outputs["ServerCertificateName"]
        )
    snapshot.match("get_server_certificate_error", e.value.response)

    snapshot.add_transformer(
        snapshot.transform.key_value("ServerCertificateName", "server-certificate-name")
    )
    snapshot.add_transformer(
        snapshot.transform.key_value("ServerCertificateId", "server-certificate-id")
    )

    @markers.aws.unknown
    def test_cfn_handle_iam_role_resource_no_role_name(self, deploy_cfn_template, aws_client):
        role_path_prefix = f"/role-prefix-{short_uid()}/"
        stack = deploy_cfn_template(template=TEST_TEMPLATE_14 % role_path_prefix)

        rs = aws_client.iam.list_roles(PathPrefix=role_path_prefix)
        assert len(rs["Roles"]) == 1

        stack.destroy()

        rs = aws_client.iam.list_roles(PathPrefix=role_path_prefix)
        assert not rs["Roles"]

    @markers.aws.validated
    def test_updating_stack_with_iam_role(self, deploy_cfn_template, aws_client):
        TEST_TEMPLATE_14 = """
        AWSTemplateFormatVersion: 2010-09-09
        Resources:
          IamRoleLambdaExecution:
            Type: 'AWS::IAM::Role'
            Properties:
              AssumeRolePolicyDocument: {}
              Path: %s
        """
        lambda_role_name = f"lambda-role-{short_uid()}"
        lambda_function_name = f"lambda-function-{short_uid()}"

        # Create stack and wait for 'CREATE_COMPLETE' status of the stack
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../../templates/template7.json"
            ),
            parameters={
                "LambdaRoleName": lambda_role_name,
                "LambdaFunctionName": lambda_function_name,
            },
        )

        # Checking required values for Lambda function and IAM Role
        list_functions = list_all_resources(
            lambda kwargs: aws_client.lambda_.list_functions(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="Functions",
        )
        all_roles = aws_client.iam.list_roles(MaxItems=1000)["Roles"]
        filtered_roles = [r["RoleName"] for r in all_roles if lambda_role_name == r["RoleName"]]
        assert len(filtered_roles) == 1

        new_function = [
            function
            for function in list_functions
            if function.get("FunctionName") == lambda_function_name
        ]
        assert len(new_function) == 1
        assert lambda_role_name in new_function[0].get("Role")

        # Generate new names for lambda and IAM Role
        lambda_role_name_new = f"lambda-role-new-{short_uid()}"
        lambda_function_name_new = f"lambda-function-new-{short_uid()}"

        # Update stack and wait for 'UPDATE_COMPLETE' status of the stack
        deploy_cfn_template(
            is_update=True,
            template_path=os.path.join(
                os.path.dirname(__file__), "../../../templates/template7.json"
            ),
            stack_name=stack.stack_name,
            parameters={
                "LambdaRoleName": lambda_role_name_new,
                "LambdaFunctionName": lambda_function_name_new,
            },
        )

        # Checking new required values for Lambda function and IAM Role

        list_functions = list_all_resources(
            lambda kwargs: aws_client.lambda_.list_functions(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="Functions",
        )

        all_roles = aws_client.iam.list_roles(MaxItems=1000)["Roles"]
        filtered_roles = [r["RoleName"] for r in all_roles if lambda_role_name_new == r["RoleName"]]
        assert len(filtered_roles) == 1

        new_function = [
            function
            for function in list_functions
            if function.get("FunctionName") == lambda_function_name_new
        ]
        assert len(new_function) == 1
        assert lambda_role_name_new in new_function[0].get("Role")
