import json
import logging
import os
import unittest

from botocore.exceptions import ClientError

from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services.iam.iam_starter import ADDITIONAL_MANAGED_POLICIES
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid
from localstack.utils.kinesis import kinesis_connector


class TestIAMIntegrations(unittest.TestCase):
    def setUp(self):
        self.iam_client = aws_stack.create_external_boto_client("iam")

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

    def test_attach_iam_role_to_new_iam_user(self):
        test_policy_document = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::example_bucket",
            },
        }
        test_user_name = "test-user"

        self.iam_client.create_user(UserName=test_user_name)
        response = self.iam_client.create_policy(
            PolicyName="test-policy", PolicyDocument=json.dumps(test_policy_document)
        )
        test_policy_arn = response["Policy"]["Arn"]
        self.assertIn(TEST_AWS_ACCOUNT_ID, test_policy_arn)

        self.iam_client.attach_user_policy(UserName=test_user_name, PolicyArn=test_policy_arn)
        attached_user_policies = self.iam_client.list_attached_user_policies(
            UserName=test_user_name
        )

        self.assertEqual(1, len(attached_user_policies["AttachedPolicies"]))
        self.assertEqual(
            test_policy_arn, attached_user_policies["AttachedPolicies"][0]["PolicyArn"]
        )

        # clean up
        self.iam_client.detach_user_policy(UserName=test_user_name, PolicyArn=test_policy_arn)
        self.iam_client.delete_policy(PolicyArn=test_policy_arn)
        self.iam_client.delete_user(UserName=test_user_name)

    def test_delete_non_existent_policy_returns_no_such_entity(self):
        non_existent_policy_arn = "arn:aws:iam::000000000000:policy/non-existent-policy"
        with self.assertRaises(ClientError) as ctx:
            self.iam_client.delete_policy(PolicyArn=non_existent_policy_arn)
        self.assertEqual("NoSuchEntity", ctx.exception.response["Error"]["Code"])

    def test_recreate_iam_role(self):
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

        rs = self.iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_policy_document),
        )
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        try:
            # Create role with same name
            self.iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_policy_document),
            )
            self.fail("This call should not be successful as the role already exists")

        except ClientError as e:
            self.assertEqual("EntityAlreadyExists", e.response["Error"]["Code"])

        # clean up
        self.iam_client.delete_role(RoleName=role_name)

    def test_create_user_with_tags(self):
        user_name = "user-role-{}".format(short_uid())

        rs = self.iam_client.create_user(
            UserName=user_name, Tags=[{"Key": "env", "Value": "production"}]
        )

        self.assertIn("Tags", rs["User"])
        self.assertEqual("env", rs["User"]["Tags"][0]["Key"])

        rs = self.iam_client.get_user(UserName=user_name)

        self.assertIn("Tags", rs["User"])
        self.assertEqual("production", rs["User"]["Tags"][0]["Value"])

        # clean up
        self.iam_client.delete_user(UserName=user_name)

    def test_attach_detach_role_policy(self):
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

        self.iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_policy_document),
        )

        policy_arn = self.iam_client.create_policy(
            PolicyName=policy_name, Path="/", PolicyDocument=json.dumps(policy_document)
        )["Policy"]["Arn"]
        policy_arns.append(policy_arn)

        # Attach some polices
        for policy_arn in policy_arns:
            rs = self.iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        try:
            # Try to delete role
            self.iam_client.delete_role(RoleName=role_name)
            self.fail("This call should not be successful as the role has policies attached")

        except ClientError as e:
            self.assertEqual("DeleteConflict", e.response["Error"]["Code"])

        for policy_arn in policy_arns:
            rs = self.iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        # clean up
        rs = self.iam_client.delete_role(RoleName=role_name)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        self.iam_client.delete_policy(PolicyArn=policy_arn)

    def test_simulate_principle_policy(self):
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

        policy_arn = self.iam_client.create_policy(
            PolicyName=policy_name, Path="/", PolicyDocument=json.dumps(policy_document)
        )["Policy"]["Arn"]

        rs = self.iam_client.simulate_principal_policy(
            PolicySourceArn=policy_arn,
            ActionNames=["s3:PutObject", "s3:GetObjectVersion"],
            ResourceArns=["arn:aws:s3:::bucket_name"],
        )
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])
        evaluation_results = rs["EvaluationResults"]
        self.assertEqual(2, len(evaluation_results))

        actions = {evaluation["EvalActionName"]: evaluation for evaluation in evaluation_results}
        self.assertIn("s3:PutObject", actions)
        self.assertEqual("explicitDeny", actions["s3:PutObject"]["EvalDecision"])
        self.assertIn("s3:GetObjectVersion", actions)
        self.assertEqual("allowed", actions["s3:GetObjectVersion"]["EvalDecision"])

    def test_create_role_with_assume_role_policy(self):
        role_name_1 = "role-{}".format(short_uid())
        role_name_2 = "role-{}".format(short_uid())

        assume_role_policy_doc = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "sts:AssumeRole",
                        "Effect": "Allow",
                        "Principal": {"AWS": ["arn:aws:iam::123412341234:root"]},
                    }
                ],
            }
        )

        self.iam_client.create_role(
            Path="/",
            RoleName=role_name_1,
            AssumeRolePolicyDocument=assume_role_policy_doc,
        )

        roles = self.iam_client.list_roles()["Roles"]
        for role in roles:
            if role["RoleName"] == role_name_1:
                self.assertEqual(assume_role_policy_doc, role["AssumeRolePolicyDocument"])

        self.iam_client.create_role(
            Path="/",
            RoleName=role_name_2,
            AssumeRolePolicyDocument=assume_role_policy_doc,
            Description="string",
        )

        roles = self.iam_client.list_roles()["Roles"]
        for role in roles:
            if role["RoleName"] in [role_name_1, role_name_2]:
                self.assertEqual(assume_role_policy_doc, role["AssumeRolePolicyDocument"])
                self.iam_client.delete_role(RoleName=role["RoleName"])

        self.iam_client.create_role(
            Path="myPath",
            RoleName=role_name_2,
            AssumeRolePolicyDocument=assume_role_policy_doc,
            Description="string",
        )

        roles = self.iam_client.list_roles(PathPrefix="my")
        self.assertEqual("myPath", roles["Roles"][0]["Path"])
        self.assertEqual(role_name_2, roles["Roles"][0]["RoleName"])
        self.assertEqual(1, len(roles["Roles"]))
