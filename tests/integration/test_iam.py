import json
import logging
import os

import pytest
from botocore.exceptions import ClientError

from localstack.aws.api.iam import Tag
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services.iam.provider import ADDITIONAL_MANAGED_POLICIES
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.strings import long_uid


class TestIAMIntegrations:
    @pytest.fixture
    def iam_client(self):
        return aws_stack.create_external_boto_client("iam")

    # TODO what does this test do?
    def test_run_kcl_with_iam_assume_role(self):
        env_vars = {}
        if os.environ.get("AWS_ASSUME_ROLE_ARN"):
            env_vars["AWS_ASSUME_ROLE_ARN"] = os.environ.get("AWS_ASSUME_ROLE_ARN")
            env_vars["AWS_ASSUME_ROLE_SESSION_NAME"] = os.environ.get(
                "AWS_ASSUME_ROLE_SESSION_NAME"
            )
            env_vars["ENV"] = os.environ.get("ENV") or "main"

            def process_records(records):
                print(records)

            # start Kinesis client
            stream_name = f"test-foobar-{short_uid()}"
            kinesis_connector.listen_to_kinesis(
                stream_name=stream_name,
                listener_func=process_records,
                env_vars=env_vars,
                kcl_log_level=logging.INFO,
                wait_until_started=True,
            )

    def test_attach_iam_role_to_new_iam_user(self, iam_client):
        test_policy_document = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::example_bucket",
            },
        }
        test_user_name = "test-user"

        iam_client.create_user(UserName=test_user_name)
        response = iam_client.create_policy(
            PolicyName="test-policy", PolicyDocument=json.dumps(test_policy_document)
        )
        test_policy_arn = response["Policy"]["Arn"]
        assert TEST_AWS_ACCOUNT_ID in test_policy_arn

        iam_client.attach_user_policy(UserName=test_user_name, PolicyArn=test_policy_arn)
        attached_user_policies = iam_client.list_attached_user_policies(UserName=test_user_name)

        assert len(attached_user_policies["AttachedPolicies"]) == 1
        assert attached_user_policies["AttachedPolicies"][0]["PolicyArn"] == test_policy_arn

        # clean up
        iam_client.detach_user_policy(UserName=test_user_name, PolicyArn=test_policy_arn)
        iam_client.delete_policy(PolicyArn=test_policy_arn)
        iam_client.delete_user(UserName=test_user_name)

        with pytest.raises(ClientError) as ctx:
            iam_client.get_user(UserName=test_user_name)
        assert ctx.typename == "NoSuchEntityException"
        assert ctx.value.response["Error"]["Code"] == "NoSuchEntity"

    def test_delete_non_existent_policy_returns_no_such_entity(self, iam_client):
        non_existent_policy_arn = "arn:aws:iam::000000000000:policy/non-existent-policy"

        with pytest.raises(ClientError) as ctx:
            iam_client.delete_policy(PolicyArn=non_existent_policy_arn)
        assert ctx.typename == "NoSuchEntityException"
        assert ctx.value.response["Error"]["Code"] == "NoSuchEntity"

    def test_recreate_iam_role(self, iam_client):
        role_name = "role-{}".format(short_uid())

        assume_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                }
            ],
        }

        rs = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_policy_document),
        )
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        try:
            # Create role with same name
            iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_policy_document),
            )
            pytest.fail("This call should not be successful as the role already exists")

        except ClientError as e:
            assert e.response["Error"]["Code"] == "EntityAlreadyExists"

        # clean up
        iam_client.delete_role(RoleName=role_name)

    def test_instance_profile_tags(self, iam_client):
        def gen_tag():
            return Tag(Key=f"key-{long_uid()}", Value=f"value-{short_uid()}")

        user_name = "user-role-{}".format(short_uid())
        iam_client.create_instance_profile(InstanceProfileName=user_name)

        tags_v0 = []
        #
        rs = iam_client.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"] == tags_v0

        tags_v1 = [gen_tag()]
        #
        rs = iam_client.tag_instance_profile(InstanceProfileName=user_name, Tags=tags_v1)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200
        #
        rs = iam_client.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"] == tags_v1

        tags_v2_new = [gen_tag() for _ in range(5)]
        tags_v2 = tags_v1 + tags_v2_new
        rs = iam_client.tag_instance_profile(InstanceProfileName=user_name, Tags=tags_v2)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200
        #
        rs = iam_client.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"] == tags_v2

        rs = iam_client.tag_instance_profile(InstanceProfileName=user_name, Tags=tags_v2)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200
        #
        rs = iam_client.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"] == tags_v2

        tags_v3_new = [gen_tag()]
        tags_v3 = tags_v1 + tags_v3_new
        target_tags_v3 = tags_v2 + tags_v3_new
        rs = iam_client.tag_instance_profile(InstanceProfileName=user_name, Tags=tags_v3)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200
        #
        rs = iam_client.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"] == target_tags_v3

        tags_v4 = tags_v1
        target_tags_v4 = target_tags_v3
        rs = iam_client.tag_instance_profile(InstanceProfileName=user_name, Tags=tags_v4)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200
        #
        rs = iam_client.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"] == target_tags_v4

        tags_u_v1 = [tag["Key"] for tag in tags_v1]
        target_tags_u_v1 = tags_v2_new + tags_v3_new
        iam_client.untag_instance_profile(InstanceProfileName=user_name, TagKeys=tags_u_v1)
        #
        rs = iam_client.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"] == target_tags_u_v1

        tags_u_v2 = [f"key-{long_uid()}"]
        target_tags_u_v2 = target_tags_u_v1
        iam_client.untag_instance_profile(InstanceProfileName=user_name, TagKeys=tags_u_v2)
        #
        rs = iam_client.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"] == target_tags_u_v2

        tags_u_v3 = [tag["Key"] for tag in target_tags_u_v1]
        target_tags_u_v3 = []
        iam_client.untag_instance_profile(InstanceProfileName=user_name, TagKeys=tags_u_v3)
        #
        rs = iam_client.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"] == target_tags_u_v3

        iam_client.delete_instance_profile(InstanceProfileName=user_name)

    def test_create_user_with_tags(self, iam_client):
        user_name = "user-role-{}".format(short_uid())

        rs = iam_client.create_user(
            UserName=user_name, Tags=[{"Key": "env", "Value": "production"}]
        )

        assert "Tags" in rs["User"]
        assert rs["User"]["Tags"][0]["Key"] == "env"

        rs = iam_client.get_user(UserName=user_name)

        assert "Tags" in rs["User"]
        assert rs["User"]["Tags"][0]["Value"] == "production"

        # clean up
        iam_client.delete_user(UserName=user_name)

    def test_attach_detach_role_policy(self, iam_client):
        role_name = "s3-role-{}".format(short_uid())
        policy_name = "s3-role-policy-{}".format(short_uid())

        policy_arns = [p["Arn"] for p in ADDITIONAL_MANAGED_POLICIES.values()]

        assume_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Principal": {"Service": "s3.amazonaws.com"},
                }
            ],
        }

        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": [
                        "s3:GetReplicationConfiguration",
                        "s3:GetObjectVersion",
                        "s3:ListBucket",
                    ],
                    "Effect": "Allow",
                    "Resource": ["arn:aws:s3:::bucket_name"],
                }
            ],
        }

        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_policy_document),
        )

        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, Path="/", PolicyDocument=json.dumps(policy_document)
        )["Policy"]["Arn"]
        policy_arns.append(policy_arn)

        # Attach some polices
        for policy_arn in policy_arns:
            rs = iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        try:
            # Try to delete role
            iam_client.delete_role(RoleName=role_name)
            pytest.fail("This call should not be successful as the role has policies attached")

        except ClientError as e:
            assert e.response["Error"]["Code"] == "DeleteConflict"

        for policy_arn in policy_arns:
            rs = iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        # clean up
        rs = iam_client.delete_role(RoleName=role_name)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        iam_client.delete_policy(PolicyArn=policy_arn)

    def test_simulate_principle_policy(self, iam_client):
        policy_name = "policy-{}".format(short_uid())
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["s3:GetObjectVersion", "s3:ListBucket"],
                    "Effect": "Allow",
                    "Resource": ["arn:aws:s3:::bucket_name"],
                }
            ],
        }

        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, Path="/", PolicyDocument=json.dumps(policy_document)
        )["Policy"]["Arn"]

        rs = iam_client.simulate_principal_policy(
            PolicySourceArn=policy_arn,
            ActionNames=["s3:PutObject", "s3:GetObjectVersion"],
            ResourceArns=["arn:aws:s3:::bucket_name"],
        )
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200
        evaluation_results = rs["EvaluationResults"]
        assert len(evaluation_results) == 2

        actions = {evaluation["EvalActionName"]: evaluation for evaluation in evaluation_results}
        assert "s3:PutObject" in actions
        assert actions["s3:PutObject"]["EvalDecision"] == "explicitDeny"
        assert "s3:GetObjectVersion" in actions
        assert actions["s3:GetObjectVersion"]["EvalDecision"] == "allowed"

    def test_create_role_with_assume_role_policy(self, iam_client):
        role_name_1 = "role-{}".format(short_uid())
        role_name_2 = "role-{}".format(short_uid())

        assume_role_policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Effect": "Allow",
                    "Principal": {"AWS": ["arn:aws:iam::123412341234:root"]},
                }
            ],
        }
        str_assume_role_policy_doc = json.dumps(assume_role_policy_doc)

        iam_client.create_role(
            Path="/",
            RoleName=role_name_1,
            AssumeRolePolicyDocument=str_assume_role_policy_doc,
        )

        roles = iam_client.list_roles()["Roles"]
        for role in roles:
            if role["RoleName"] == role_name_1:
                assert role["AssumeRolePolicyDocument"] == assume_role_policy_doc

        iam_client.create_role(
            Path="/",
            RoleName=role_name_2,
            AssumeRolePolicyDocument=str_assume_role_policy_doc,
            Description="string",
        )

        roles = iam_client.list_roles()["Roles"]
        for role in roles:
            if role["RoleName"] in [role_name_1, role_name_2]:
                assert role["AssumeRolePolicyDocument"] == assume_role_policy_doc
                iam_client.delete_role(RoleName=role["RoleName"])

        iam_client.create_role(
            Path="myPath",
            RoleName=role_name_2,
            AssumeRolePolicyDocument=str_assume_role_policy_doc,
            Description="string",
        )

        roles = iam_client.list_roles(PathPrefix="my")
        assert roles["Roles"][0]["Path"] == "myPath"
        assert roles["Roles"][0]["RoleName"] == role_name_2
        assert len(roles["Roles"]) == 1
