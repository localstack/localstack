import functools
import json
import logging
from urllib.parse import quote_plus

import pytest
from botocore.exceptions import ClientError

from localstack.aws.api.iam import Tag
from localstack.services.iam.iam_patches import ADDITIONAL_MANAGED_POLICIES
from localstack.testing.aws.util import create_client_with_keys, wait_for_user
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer_utility import PATTERN_UUID
from localstack.utils.aws.arns import get_partition
from localstack.utils.common import short_uid
from localstack.utils.strings import long_uid
from localstack.utils.sync import retry

LOG = logging.getLogger(__name__)

GET_USER_POLICY_DOC = """{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "sgetuser",
            "Effect": "Allow",
            "Action": ["iam:GetUser"],
            "Resource": "*"
        }
    ]
}"""


class TestIAMExtensions:
    @markers.aws.validated
    def test_get_user_without_username_as_user(self, create_user, aws_client, region_name):
        user_name = f"user-{short_uid()}"
        policy_name = f"policy={short_uid()}"
        create_user(UserName=user_name)
        aws_client.iam.put_user_policy(
            UserName=user_name, PolicyName=policy_name, PolicyDocument=GET_USER_POLICY_DOC
        )
        account_id = aws_client.sts.get_caller_identity()["Account"]
        keys = aws_client.iam.create_access_key(UserName=user_name)["AccessKey"]
        wait_for_user(keys, region_name)
        iam_client_as_user = create_client_with_keys("iam", keys=keys, region_name=region_name)
        user_response = iam_client_as_user.get_user()
        user = user_response["User"]
        assert user["UserName"] == user_name
        assert user["Arn"] == f"arn:{get_partition(region_name)}:iam::{account_id}:user/{user_name}"

    @markers.aws.only_localstack
    def test_get_user_without_username_as_root(self, aws_client):
        """Test get_user on root account. Marked only localstack, since we usually cannot access as root directly"""
        account_id = aws_client.sts.get_caller_identity()["Account"]
        user_response = aws_client.iam.get_user()
        user = user_response["User"]
        assert user["UserId"] == account_id
        assert user["Arn"] == f"arn:aws:iam::{account_id}:root"

    @markers.aws.validated
    def test_get_user_without_username_as_role(
        self, create_role, wait_and_assume_role, aws_client, region_name
    ):
        role_name = f"role-{short_uid()}"
        policy_name = f"policy={short_uid()}"
        session_name = f"session-{short_uid()}"
        account_arn = aws_client.sts.get_caller_identity()["Arn"]
        assume_policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Principal": {"AWS": account_arn},
                    "Effect": "Allow",
                }
            ],
        }
        created_role_arn = create_role(
            RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume_policy_doc)
        )["Role"]["Arn"]
        aws_client.iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=GET_USER_POLICY_DOC
        )
        keys = wait_and_assume_role(role_arn=created_role_arn, session_name=session_name)
        iam_client_as_role = create_client_with_keys("iam", keys=keys, region_name=region_name)
        with pytest.raises(ClientError) as e:
            iam_client_as_role.get_user()
        e.match("Must specify userName when calling with non-User credentials")

    @markers.aws.validated
    def test_create_user_with_permission_boundary(self, create_user, create_policy, aws_client):
        user_name = f"user-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        policy_arn = create_policy(PolicyName=policy_name, PolicyDocument=GET_USER_POLICY_DOC)[
            "Policy"
        ]["Arn"]
        create_user_reply = create_user(UserName=user_name, PermissionsBoundary=policy_arn)
        assert "PermissionsBoundary" in create_user_reply["User"]
        assert {
            "PermissionsBoundaryArn": policy_arn,
            "PermissionsBoundaryType": "Policy",
        } == create_user_reply["User"]["PermissionsBoundary"]
        get_user_reply = aws_client.iam.get_user(UserName=user_name)
        assert "PermissionsBoundary" in get_user_reply["User"]
        assert {
            "PermissionsBoundaryArn": policy_arn,
            "PermissionsBoundaryType": "Policy",
        } == get_user_reply["User"]["PermissionsBoundary"]
        aws_client.iam.delete_user_permissions_boundary(UserName=user_name)
        get_user_reply = aws_client.iam.get_user(UserName=user_name)
        assert "PermissionsBoundary" not in get_user_reply["User"]

    @markers.aws.validated
    def test_create_user_add_permission_boundary_afterwards(
        self, create_user, create_policy, aws_client
    ):
        user_name = f"user-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        policy_arn = create_policy(PolicyName=policy_name, PolicyDocument=GET_USER_POLICY_DOC)[
            "Policy"
        ]["Arn"]
        create_user_reply = create_user(UserName=user_name)
        assert "PermissionsBoundary" not in create_user_reply["User"]
        get_user_reply = aws_client.iam.get_user(UserName=user_name)
        assert "PermissionsBoundary" not in get_user_reply["User"]
        aws_client.iam.put_user_permissions_boundary(
            UserName=user_name, PermissionsBoundary=policy_arn
        )
        get_user_reply = aws_client.iam.get_user(UserName=user_name)
        assert "PermissionsBoundary" in get_user_reply["User"]
        assert {
            "PermissionsBoundaryArn": policy_arn,
            "PermissionsBoundaryType": "Policy",
        } == get_user_reply["User"]["PermissionsBoundary"]
        aws_client.iam.delete_user_permissions_boundary(UserName=user_name)
        get_user_reply = aws_client.iam.get_user(UserName=user_name)
        assert "PermissionsBoundary" not in get_user_reply["User"]

    @markers.aws.validated
    def test_create_role_with_malformed_assume_role_policy_document(self, aws_client, snapshot):
        role_name = f"role-{short_uid()}"
        # The error in this document is the trailing comma after `"Effect": "Allow"`
        assume_role_policy_document = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Action": "sts:AssumeRole",
              "Principal": "*",
              "Effect": "Allow",
            }
          ]
        }
        """
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_role(
                RoleName=role_name, AssumeRolePolicyDocument=assume_role_policy_document
            )
        snapshot.match("invalid-json", e.value.response)

    @markers.aws.validated
    def test_role_with_path_lifecycle(self, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.iam_api())
        role_name = f"role-{short_uid()}"
        path = f"/path{short_uid()}/"
        snapshot.add_transformer(snapshot.transform.regex(path, "<path>"))
        assume_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Effect": "Allow",
                }
            ],
        }

        create_role_response = aws_client.iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_policy_document),
            Path=path,
        )
        snapshot.match("create-role-response", create_role_response)

        get_role_response = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-response", get_role_response)

        delete_role_response = aws_client.iam.delete_role(RoleName=role_name)
        snapshot.match("delete-role-response", delete_role_response)


class TestIAMIntegrations:
    @markers.aws.validated
    def test_attach_iam_role_to_new_iam_user(
        self, aws_client, account_id, create_user, create_policy
    ):
        test_policy_document = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::example_bucket",
            },
        }
        test_user_name = f"test-user-{short_uid()}"

        create_user(UserName=test_user_name)
        response = create_policy(
            PolicyName=f"test-policy-{short_uid()}", PolicyDocument=json.dumps(test_policy_document)
        )
        test_policy_arn = response["Policy"]["Arn"]
        assert account_id in test_policy_arn

        aws_client.iam.attach_user_policy(UserName=test_user_name, PolicyArn=test_policy_arn)
        attached_user_policies = aws_client.iam.list_attached_user_policies(UserName=test_user_name)

        assert len(attached_user_policies["AttachedPolicies"]) == 1
        assert attached_user_policies["AttachedPolicies"][0]["PolicyArn"] == test_policy_arn

        # clean up
        aws_client.iam.detach_user_policy(UserName=test_user_name, PolicyArn=test_policy_arn)
        aws_client.iam.delete_policy(PolicyArn=test_policy_arn)
        aws_client.iam.delete_user(UserName=test_user_name)

        with pytest.raises(ClientError) as ctx:
            aws_client.iam.get_user(UserName=test_user_name)
        assert ctx.typename == "NoSuchEntityException"
        assert ctx.value.response["Error"]["Code"] == "NoSuchEntity"

    @markers.aws.validated
    def test_delete_non_existent_policy_returns_no_such_entity(
        self, aws_client, snapshot, account_id
    ):
        non_existent_policy_arn = f"arn:aws:iam::{account_id}:policy/non-existent-policy"

        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_policy(PolicyArn=non_existent_policy_arn)
        snapshot.match("delete-non-existent-policy-exc", e.value.response)

    @markers.aws.validated
    def test_recreate_iam_role(self, aws_client, create_role):
        role_name = f"role-{short_uid()}"

        assume_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Effect": "Allow",
                }
            ],
        }

        rs = create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_policy_document),
        )
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        try:
            # Create role with same name
            aws_client.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_policy_document),
            )
            pytest.fail("This call should not be successful as the role already exists")

        except ClientError as e:
            assert e.response["Error"]["Code"] == "EntityAlreadyExists"

    @markers.aws.validated
    def test_instance_profile_tags(self, aws_client, cleanups):
        def gen_tag():
            return Tag(Key=f"key-{long_uid()}", Value=f"value-{short_uid()}")

        def _sort_key(entry):
            return entry["Key"]

        user_name = f"user-role-{short_uid()}"
        aws_client.iam.create_instance_profile(InstanceProfileName=user_name)
        cleanups.append(
            lambda: aws_client.iam.delete_instance_profile(InstanceProfileName=user_name)
        )

        tags_v0 = []
        #
        rs = aws_client.iam.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"].sort(key=_sort_key) == tags_v0.sort(key=_sort_key)

        tags_v1 = [gen_tag()]
        #
        rs = aws_client.iam.tag_instance_profile(InstanceProfileName=user_name, Tags=tags_v1)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200
        #
        rs = aws_client.iam.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"].sort(key=_sort_key) == tags_v1.sort(key=_sort_key)

        tags_v2_new = [gen_tag() for _ in range(5)]
        tags_v2 = tags_v1 + tags_v2_new
        rs = aws_client.iam.tag_instance_profile(InstanceProfileName=user_name, Tags=tags_v2)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200
        #
        rs = aws_client.iam.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"].sort(key=_sort_key) == tags_v2.sort(key=_sort_key)

        rs = aws_client.iam.tag_instance_profile(InstanceProfileName=user_name, Tags=tags_v2)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200
        #
        rs = aws_client.iam.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"].sort(key=_sort_key) == tags_v2.sort(key=_sort_key)

        tags_v3_new = [gen_tag()]
        tags_v3 = tags_v1 + tags_v3_new
        target_tags_v3 = tags_v2 + tags_v3_new
        rs = aws_client.iam.tag_instance_profile(InstanceProfileName=user_name, Tags=tags_v3)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200
        #
        rs = aws_client.iam.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"].sort(key=_sort_key) == target_tags_v3.sort(key=_sort_key)

        tags_v4 = tags_v1
        target_tags_v4 = target_tags_v3
        rs = aws_client.iam.tag_instance_profile(InstanceProfileName=user_name, Tags=tags_v4)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200
        #
        rs = aws_client.iam.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"].sort(key=_sort_key) == target_tags_v4.sort(key=_sort_key)

        tags_u_v1 = [tag["Key"] for tag in tags_v1]
        target_tags_u_v1 = tags_v2_new + tags_v3_new
        aws_client.iam.untag_instance_profile(InstanceProfileName=user_name, TagKeys=tags_u_v1)
        #
        rs = aws_client.iam.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"].sort(key=_sort_key) == target_tags_u_v1.sort(key=_sort_key)

        tags_u_v2 = [f"key-{long_uid()}"]
        target_tags_u_v2 = target_tags_u_v1
        aws_client.iam.untag_instance_profile(InstanceProfileName=user_name, TagKeys=tags_u_v2)
        #
        rs = aws_client.iam.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"].sort(key=_sort_key) == target_tags_u_v2.sort(key=_sort_key)

        tags_u_v3 = [tag["Key"] for tag in target_tags_u_v1]
        target_tags_u_v3 = []
        aws_client.iam.untag_instance_profile(InstanceProfileName=user_name, TagKeys=tags_u_v3)
        #
        rs = aws_client.iam.list_instance_profile_tags(InstanceProfileName=user_name)
        assert rs["Tags"].sort(key=_sort_key) == target_tags_u_v3.sort(key=_sort_key)

    @markers.aws.validated
    def test_create_user_with_tags(self, aws_client):
        user_name = f"user-role-{short_uid()}"

        rs = aws_client.iam.create_user(
            UserName=user_name, Tags=[{"Key": "env", "Value": "production"}]
        )

        assert "Tags" in rs["User"]
        assert rs["User"]["Tags"][0]["Key"] == "env"

        rs = aws_client.iam.get_user(UserName=user_name)

        assert "Tags" in rs["User"]
        assert rs["User"]["Tags"][0]["Value"] == "production"

        # clean up
        aws_client.iam.delete_user(UserName=user_name)

    @markers.aws.validated
    def test_attach_detach_role_policy(self, aws_client, region_name):
        role_name = f"s3-role-{short_uid()}"
        policy_name = f"s3-role-policy-{short_uid()}"

        policy_arns = [p["Arn"] for p in ADDITIONAL_MANAGED_POLICIES.values()]
        policy_arns = [
            arn.replace("arn:aws:", f"arn:{get_partition(region_name)}:") for arn in policy_arns
        ]

        assume_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Effect": "Allow",
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
                    "Resource": [f"arn:{get_partition(region_name)}:s3:::bucket_name"],
                }
            ],
        }

        aws_client.iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_policy_document),
        )

        policy_arn = aws_client.iam.create_policy(
            PolicyName=policy_name, Path="/", PolicyDocument=json.dumps(policy_document)
        )["Policy"]["Arn"]
        policy_arns.append(policy_arn)

        # Attach some polices
        for policy_arn in policy_arns:
            rs = aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        try:
            # Try to delete role
            aws_client.iam.delete_role(RoleName=role_name)
            pytest.fail("This call should not be successful as the role has policies attached")

        except ClientError as e:
            assert e.response["Error"]["Code"] == "DeleteConflict"

        for policy_arn in policy_arns:
            rs = aws_client.iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        # clean up
        rs = aws_client.iam.delete_role(RoleName=role_name)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        aws_client.iam.delete_policy(PolicyArn=policy_arn)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..EvaluationResults"])
    @pytest.mark.parametrize("arn_type", ["role", "group", "user"])
    def test_simulate_principle_policy(
        self,
        arn_type,
        aws_client,
        create_role,
        create_policy,
        create_user,
        s3_bucket,
        snapshot,
        cleanups,
    ):
        bucket = s3_bucket
        snapshot.add_transformer(snapshot.transform.regex(bucket, "bucket"))
        snapshot.add_transformer(snapshot.transform.key_value("SourcePolicyId"))

        policy_arn = create_policy(
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": {
                        "Sid": "",
                        "Effect": "Allow",
                        "Action": "s3:PutObject",
                        "Resource": "*",
                    },
                }
            )
        )["Policy"]["Arn"]

        if arn_type == "role":
            role_name = f"role-{short_uid()}"
            role_arn = create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": {
                            "Sid": "",
                            "Effect": "Allow",
                            "Principal": {"Service": "apigateway.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        },
                    }
                ),
            )["Role"]["Arn"]
            aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            arn = role_arn

        elif arn_type == "group":
            group_name = f"group-{short_uid()}"
            group = aws_client.iam.create_group(GroupName=group_name)["Group"]
            cleanups.append(lambda _: aws_client.iam.delete_group(GroupName=group_name))
            aws_client.iam.attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
            arn = group["Arn"]

        else:
            user_name = f"user-{short_uid()}"
            user = create_user(UserName=user_name)["User"]
            aws_client.iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
            arn = user["Arn"]

        rs = aws_client.iam.simulate_principal_policy(
            PolicySourceArn=arn,
            ActionNames=["s3:PutObject", "s3:GetObjectVersion"],
            ResourceArns=[f"arn:aws:s3:::{bucket}"],
        )

        snapshot.match("response", rs)

    @markers.aws.validated
    def test_create_role_with_assume_role_policy(self, aws_client, account_id, create_role):
        role_name_1 = f"role-{short_uid()}"
        role_name_2 = f"role-{short_uid()}"

        assume_role_policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                }
            ],
        }
        str_assume_role_policy_doc = json.dumps(assume_role_policy_doc)

        create_role(
            Path="/",
            RoleName=role_name_1,
            AssumeRolePolicyDocument=str_assume_role_policy_doc,
        )

        roles = aws_client.iam.list_roles()["Roles"]
        for role in roles:
            if role["RoleName"] == role_name_1:
                assert role["AssumeRolePolicyDocument"] == assume_role_policy_doc

        create_role(
            Path="/",
            RoleName=role_name_2,
            AssumeRolePolicyDocument=str_assume_role_policy_doc,
            Description="string",
        )

        roles = aws_client.iam.list_roles()["Roles"]
        for role in roles:
            if role["RoleName"] in [role_name_1, role_name_2]:
                assert role["AssumeRolePolicyDocument"] == assume_role_policy_doc
                aws_client.iam.delete_role(RoleName=role["RoleName"])

        create_role(
            Path="/myPath/",
            RoleName=role_name_2,
            AssumeRolePolicyDocument=str_assume_role_policy_doc,
            Description="string",
        )

        roles = aws_client.iam.list_roles(PathPrefix="/my")
        assert len(roles["Roles"]) == 1
        assert roles["Roles"][0]["Path"] == "/myPath/"
        assert roles["Roles"][0]["RoleName"] == role_name_2

    @markers.aws.validated
    @pytest.mark.skip
    @pytest.mark.parametrize(
        "service_name, expected_role",
        [
            ("ecs.amazonaws.com", "AWSServiceRoleForECS"),
            ("eks.amazonaws.com", "AWSServiceRoleForAmazonEKS"),
        ],
    )
    def test_service_linked_role_name_should_match_aws(
        self, service_name, expected_role, aws_client
    ):
        role_name = None
        try:
            service_linked_role = aws_client.iam.create_service_linked_role(
                AWSServiceName=service_name
            )
            role_name = service_linked_role["Role"]["RoleName"]
            assert role_name == expected_role
        finally:
            if role_name:
                aws_client.iam.delete_service_linked_role(RoleName=role_name)

    @markers.aws.validated
    def test_update_assume_role_policy(self, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.iam_api())

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": ["ec2.amazonaws.com"]},
                    "Action": ["sts:AssumeRole"],
                }
            ],
        }

        role_name = f"role-{short_uid()}"
        result = aws_client.iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(policy),
        )
        snapshot.match("created_role", result)
        try:
            result = aws_client.iam.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(policy),
            )
            snapshot.match("updated_policy", result)
        finally:
            aws_client.iam.delete_role(RoleName=role_name)

    @markers.aws.validated
    def test_create_describe_role(self, snapshot, aws_client, create_role, cleanups):
        snapshot.add_transformer(snapshot.transform.iam_api())
        path_prefix = f"/{short_uid()}/"
        snapshot.add_transformer(snapshot.transform.regex(path_prefix, "/<path-prefix>/"))

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        role_name = f"role-{short_uid()}"
        create_role_result = create_role(
            RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Path=path_prefix
        )
        snapshot.match("create_role_result", create_role_result)
        get_role_result = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get_role_result", get_role_result)

        list_roles_result = aws_client.iam.list_roles(PathPrefix=path_prefix)
        snapshot.match("list_roles_result", list_roles_result)

    @markers.aws.validated
    def test_list_roles_with_permission_boundary(
        self, snapshot, aws_client, create_role, create_policy, cleanups
    ):
        snapshot.add_transformer(snapshot.transform.iam_api())
        path_prefix = f"/{short_uid()}/"
        snapshot.add_transformer(snapshot.transform.regex(path_prefix, "/<path-prefix>/"))

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        permission_boundary = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["lambda:ListFunctions"], "Resource": ["*"]}
            ],
        }

        role_name = f"role-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        result = create_role(
            RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Path=path_prefix
        )
        snapshot.match("created_role", result)
        policy_arn = create_policy(
            PolicyName=policy_name, PolicyDocument=json.dumps(permission_boundary)
        )["Policy"]["Arn"]

        aws_client.iam.put_role_permissions_boundary(
            RoleName=role_name, PermissionsBoundary=policy_arn
        )
        cleanups.append(lambda: aws_client.iam.delete_role_permissions_boundary(RoleName=role_name))

        list_roles_result = aws_client.iam.list_roles(PathPrefix=path_prefix)
        snapshot.match("list_roles_result", list_roles_result)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Policy.IsAttachable",
            "$..Policy.PermissionsBoundaryUsageCount",
            "$..Policy.Tags",
        ]
    )
    def test_role_attach_policy(self, snapshot, aws_client, create_role, create_policy):
        snapshot.add_transformer(snapshot.transform.iam_api())

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["lambda:ListFunctions"], "Resource": ["*"]}
            ],
        }

        role_name = f"test-role-{short_uid()}"
        policy_name = f"test-policy-{short_uid()}"
        create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
        create_policy_response = create_policy(
            PolicyName=policy_name, PolicyDocument=json.dumps(policy_document)
        )
        snapshot.match("create_policy_response", create_policy_response)
        policy_arn = create_policy_response["Policy"]["Arn"]

        with pytest.raises(ClientError) as e:
            aws_client.iam.attach_role_policy(
                RoleName=role_name, PolicyArn="longpolicynamebutnoarn"
            )
        snapshot.match("non_existent_malformed_policy_arn", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_name)
        snapshot.match("existing_policy_name_provided", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=f"{policy_arn}123")
        snapshot.match("valid_arn_not_existent", e.value.response)

        attach_policy_response = aws_client.iam.attach_role_policy(
            RoleName=role_name, PolicyArn=policy_arn
        )
        snapshot.match("valid_policy_arn", attach_policy_response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Policy.IsAttachable",
            "$..Policy.PermissionsBoundaryUsageCount",
            "$..Policy.Tags",
        ]
    )
    def test_user_attach_policy(self, snapshot, aws_client, create_user, create_policy):
        snapshot.add_transformer(snapshot.transform.iam_api())

        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["lambda:ListFunctions"], "Resource": ["*"]}
            ],
        }

        user_name = f"test-role-{short_uid()}"
        policy_name = f"test-policy-{short_uid()}"
        create_user(UserName=user_name)
        create_policy_response = create_policy(
            PolicyName=policy_name, PolicyDocument=json.dumps(policy_document)
        )
        snapshot.match("create_policy_response", create_policy_response)
        policy_arn = create_policy_response["Policy"]["Arn"]

        with pytest.raises(ClientError) as e:
            aws_client.iam.attach_user_policy(
                UserName=user_name, PolicyArn="longpolicynamebutnoarn"
            )
        snapshot.match("non_existent_malformed_policy_arn", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.attach_user_policy(UserName=user_name, PolicyArn=policy_name)
        snapshot.match("existing_policy_name_provided", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.attach_user_policy(UserName=user_name, PolicyArn=f"{policy_arn}123")
        snapshot.match("valid_arn_not_existent", e.value.response)

        attach_policy_response = aws_client.iam.attach_user_policy(
            UserName=user_name, PolicyArn=policy_arn
        )
        snapshot.match("valid_policy_arn", attach_policy_response)


class TestIAMPolicyEncoding:
    @markers.aws.validated
    def test_put_user_policy_encoding(self, snapshot, aws_client, create_user, region_name):
        snapshot.add_transformer(snapshot.transform.iam_api())

        target_arn = quote_plus(f"arn:aws:apigateway:{region_name}::/restapis/aaeeieije")
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["apigatway:PUT"],
                    "Resource": [f"arn:aws:apigateway:{region_name}::/tags/{target_arn}"],
                }
            ],
        }

        user_name = f"test-user-{short_uid()}"
        policy_name = f"test-policy-{short_uid()}"
        create_user(UserName=user_name)

        aws_client.iam.put_user_policy(
            UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document)
        )
        get_policy_response = aws_client.iam.get_user_policy(
            UserName=user_name, PolicyName=policy_name
        )
        snapshot.match("get-policy-response", get_policy_response)

    @markers.aws.validated
    def test_put_role_policy_encoding(self, snapshot, aws_client, create_role, region_name):
        snapshot.add_transformer(snapshot.transform.iam_api())

        target_arn = quote_plus(f"arn:aws:apigateway:{region_name}::/restapis/aaeeieije")
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["apigatway:PUT"],
                    "Resource": [f"arn:aws:apigateway:{region_name}::/tags/{target_arn}"],
                }
            ],
        }
        assume_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Effect": "Allow",
                    "Condition": {"StringEquals": {"aws:SourceArn": target_arn}},
                }
            ],
        }

        role_name = f"test-role-{short_uid()}"
        policy_name = f"test-policy-{short_uid()}"
        path = f"/{short_uid()}/"
        snapshot.add_transformer(snapshot.transform.key_value("Path"))
        create_role_response = create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_policy_document),
            Path=path,
        )
        snapshot.match("create-role-response", create_role_response)

        aws_client.iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document)
        )
        get_policy_response = aws_client.iam.get_role_policy(
            RoleName=role_name, PolicyName=policy_name
        )
        snapshot.match("get-policy-response", get_policy_response)

        get_role_response = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-response", get_role_response)

        list_roles_response = aws_client.iam.list_roles(PathPrefix=path)
        snapshot.match("list-roles-response", list_roles_response)

    @markers.aws.validated
    def test_put_group_policy_encoding(self, snapshot, aws_client, region_name, cleanups):
        snapshot.add_transformer(snapshot.transform.iam_api())

        # create quoted target arn
        target_arn = quote_plus(f"arn:aws:apigateway:{region_name}::/restapis/aaeeieije")
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["apigatway:PUT"],
                    "Resource": [f"arn:aws:apigateway:{region_name}::/tags/{target_arn}"],
                }
            ],
        }

        group_name = f"test-group-{short_uid()}"
        policy_name = f"test-policy-{short_uid()}"
        aws_client.iam.create_group(GroupName=group_name)
        cleanups.append(lambda: aws_client.iam.delete_group(GroupName=group_name))

        aws_client.iam.put_group_policy(
            GroupName=group_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document)
        )
        cleanups.append(
            lambda: aws_client.iam.delete_group_policy(GroupName=group_name, PolicyName=policy_name)
        )

        get_policy_response = aws_client.iam.get_group_policy(
            GroupName=group_name, PolicyName=policy_name
        )
        snapshot.match("get-policy-response", get_policy_response)


class TestIAMServiceSpecificCredentials:
    @pytest.fixture(autouse=True)
    def register_snapshot_transformers(self, snapshot):
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("ServicePassword"))
        snapshot.add_transformer(snapshot.transform.key_value("ServiceSpecificCredentialId"))

    @pytest.fixture
    def create_service_specific_credential(self, aws_client):
        username_id_pairs = []

        def _create_service_specific_credential(*args, **kwargs):
            response = aws_client.iam.create_service_specific_credential(*args, **kwargs)
            username_id_pairs.append(
                (
                    response["ServiceSpecificCredential"]["ServiceSpecificCredentialId"],
                    response["ServiceSpecificCredential"]["UserName"],
                )
            )
            return response

        yield _create_service_specific_credential

        for credential_id, user_name in username_id_pairs:
            try:
                aws_client.iam.delete_service_specific_credential(
                    ServiceSpecificCredentialId=credential_id, UserName=user_name
                )
            except Exception:
                LOG.debug(
                    "Unable to delete service specific credential '%s' for user name '%s'",
                    credential_id,
                    user_name,
                )

    @markers.aws.validated
    @pytest.mark.parametrize(
        "service_name", ["codecommit.amazonaws.com", "cassandra.amazonaws.com"]
    )
    def test_service_specific_credential_lifecycle(
        self, aws_client, create_user, snapshot, service_name
    ):
        """Test the lifecycle of service specific credentials."""
        user_name = f"user-{short_uid()}"
        create_user_response = create_user(UserName=user_name)
        snapshot.match("create-user-response", create_user_response)

        # create
        create_service_specific_credential_response = (
            aws_client.iam.create_service_specific_credential(
                UserName=user_name, ServiceName=service_name
            )
        )
        snapshot.match(
            "create-service-specific-credential-response",
            create_service_specific_credential_response,
        )
        credential_id = create_service_specific_credential_response["ServiceSpecificCredential"][
            "ServiceSpecificCredentialId"
        ]

        # list
        list_service_specific_credentials_response = (
            aws_client.iam.list_service_specific_credentials(
                UserName=user_name, ServiceName=service_name
            )
        )
        snapshot.match(
            "list-service-specific-credentials-response-before-update",
            list_service_specific_credentials_response,
        )

        # update
        update_service_specific_credential_response = (
            aws_client.iam.update_service_specific_credential(
                UserName=user_name, ServiceSpecificCredentialId=credential_id, Status="Inactive"
            )
        )
        snapshot.match(
            "update-service-specific-credential-response",
            update_service_specific_credential_response,
        )

        # list after update
        list_service_specific_credentials_response = (
            aws_client.iam.list_service_specific_credentials(
                UserName=user_name, ServiceName=service_name
            )
        )
        snapshot.match(
            "list-service-specific-credentials-response-after-update",
            list_service_specific_credentials_response,
        )

        # reset
        reset_service_specific_credential_response = (
            aws_client.iam.reset_service_specific_credential(
                UserName=user_name, ServiceSpecificCredentialId=credential_id
            )
        )
        snapshot.match(
            "reset-service-specific-credential-response", reset_service_specific_credential_response
        )

        # delete
        delete_service_specific_credential_response = (
            aws_client.iam.delete_service_specific_credential(
                ServiceSpecificCredentialId=credential_id, UserName=user_name
            )
        )
        snapshot.match(
            "delete-service-specific-credentials-response",
            delete_service_specific_credential_response,
        )

    @markers.aws.validated
    def test_create_service_specific_credential_invalid_user(self, aws_client, snapshot):
        """Use invalid users for the create operation"""
        user_name = "non-existent-user"
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_service_specific_credential(
                UserName=user_name, ServiceName="codecommit.amazonaws.com"
            )
        snapshot.match("invalid-user-name-exception", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.create_service_specific_credential(
                UserName=user_name, ServiceName="nonexistentservice.amazonaws.com"
            )
        snapshot.match("invalid-user-and-service-exception", e.value.response)

    @markers.aws.validated
    def test_create_service_specific_credential_invalid_service(
        self, aws_client, create_user, snapshot
    ):
        """Test different scenarios of invalid service names passed to the create operation"""
        user_name = f"user-{short_uid()}"
        create_user_response = create_user(UserName=user_name)
        snapshot.match("create-user-response", create_user_response)

        # a bogus service which does not exist on AWS
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_service_specific_credential(
                UserName=user_name, ServiceName="nonexistentservice.amazonaws.com"
            )
        snapshot.match("invalid-service-exception", e.value.response)

        # a random string not even ending in amazonaws.com
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_service_specific_credential(
                UserName=user_name, ServiceName="o3on3n3onosneo"
            )
        snapshot.match("invalid-service-completely-malformed-exception", e.value.response)

        # existing service, which is not supported by service specific credentials
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_service_specific_credential(
                UserName=user_name, ServiceName="lambda.amazonaws.com"
            )
        snapshot.match("invalid-service-existing-but-unsupported-exception", e.value.response)

    @markers.aws.validated
    def test_list_service_specific_credential_different_service(
        self, aws_client, create_user, snapshot, create_service_specific_credential
    ):
        """Test different scenarios of invalid or wrong service names passed to the list operation"""
        user_name = f"user-{short_uid()}"
        create_user_response = create_user(UserName=user_name)
        snapshot.match("create-user-response", create_user_response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.list_service_specific_credentials(
                UserName=user_name, ServiceName="nonexistentservice.amazonaws.com"
            )
        snapshot.match("list-service-specific-credentials-invalid-service", e.value.response)

        # Create a proper credential for codecommit
        create_service_specific_credential_response = (
            aws_client.iam.create_service_specific_credential(
                UserName=user_name, ServiceName="codecommit.amazonaws.com"
            )
        )
        snapshot.match(
            "create-service-specific-credential-response",
            create_service_specific_credential_response,
        )

        # List credentials for cassandra
        list_service_specific_credentials_response = (
            aws_client.iam.list_service_specific_credentials(
                UserName=user_name, ServiceName="cassandra.amazonaws.com"
            )
        )
        snapshot.match(
            "list-service-specific-credentials-response-wrong-service",
            list_service_specific_credentials_response,
        )

    @markers.aws.validated
    def test_delete_user_after_service_credential_created(
        self, aws_client, create_user, snapshot, create_service_specific_credential
    ):
        """Try deleting a user with active service credentials"""
        user_name = f"user-{short_uid()}"
        create_user_response = create_user(UserName=user_name)
        snapshot.match("create-user-response", create_user_response)

        # Create a credential
        create_service_specific_credential_response = create_service_specific_credential(
            UserName=user_name, ServiceName="codecommit.amazonaws.com"
        )
        snapshot.match(
            "create-service-specific-credential-response",
            create_service_specific_credential_response,
        )

        # delete user
        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_user(UserName=user_name)
        snapshot.match("delete-user-existing-credential", e.value.response)

    @markers.aws.validated
    def test_id_match_user_mismatch(
        self, aws_client, create_user, snapshot, create_service_specific_credential
    ):
        """Test operations with valid ids, but invalid users"""
        user_name = f"user-{short_uid()}"
        wrong_user_name = "wrong-user-name"
        create_user_response = create_user(UserName=user_name)
        snapshot.match("create-user-response", create_user_response)

        create_service_specific_credential_response = create_service_specific_credential(
            UserName=user_name, ServiceName="codecommit.amazonaws.com"
        )
        snapshot.match(
            "create-service-specific-credential-response",
            create_service_specific_credential_response,
        )
        credential_id = create_service_specific_credential_response["ServiceSpecificCredential"][
            "ServiceSpecificCredentialId"
        ]

        # update
        with pytest.raises(ClientError) as e:
            aws_client.iam.update_service_specific_credential(
                UserName=wrong_user_name,
                ServiceSpecificCredentialId=credential_id,
                Status="Inactive",
            )
        snapshot.match("update-wrong-user-name", e.value.response)

        # reset
        with pytest.raises(ClientError) as e:
            aws_client.iam.reset_service_specific_credential(
                UserName=wrong_user_name, ServiceSpecificCredentialId=credential_id
            )
        snapshot.match("reset-wrong-user-name", e.value.response)

        # delete
        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_service_specific_credential(
                UserName=wrong_user_name, ServiceSpecificCredentialId=credential_id
            )
        snapshot.match("delete-wrong-user-name", e.value.response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "wrong_credential_id",
        ["totally-wrong-credential-id-with-hyphens", "satisfiesregexbutstillinvalid"],
    )
    def test_user_match_id_mismatch(
        self,
        aws_client,
        create_user,
        snapshot,
        create_service_specific_credential,
        wrong_credential_id,
    ):
        """Test operations with valid usernames, but invalid ids"""
        user_name = f"user-{short_uid()}"
        create_user_response = create_user(UserName=user_name)
        snapshot.match("create-user-response", create_user_response)

        create_service_specific_credential_response = create_service_specific_credential(
            UserName=user_name, ServiceName="codecommit.amazonaws.com"
        )
        snapshot.match(
            "create-service-specific-credential-response",
            create_service_specific_credential_response,
        )

        # update
        with pytest.raises(ClientError) as e:
            aws_client.iam.update_service_specific_credential(
                UserName=user_name,
                ServiceSpecificCredentialId=wrong_credential_id,
                Status="Inactive",
            )
        snapshot.match("update-wrong-id", e.value.response)

        # reset
        with pytest.raises(ClientError) as e:
            aws_client.iam.reset_service_specific_credential(
                UserName=user_name, ServiceSpecificCredentialId=wrong_credential_id
            )
        snapshot.match("reset-wrong-id", e.value.response)

        # delete
        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_service_specific_credential(
                UserName=user_name, ServiceSpecificCredentialId=wrong_credential_id
            )
        snapshot.match("delete-wrong-id", e.value.response)

    @markers.aws.validated
    def test_invalid_update_parameters(
        self, aws_client, create_user, snapshot, create_service_specific_credential
    ):
        """Try updating a service specific credential with invalid values"""
        user_name = f"user-{short_uid()}"
        create_user_response = create_user(UserName=user_name)
        snapshot.match("create-user-response", create_user_response)

        create_service_specific_credential_response = create_service_specific_credential(
            UserName=user_name, ServiceName="codecommit.amazonaws.com"
        )
        snapshot.match(
            "create-service-specific-credential-response",
            create_service_specific_credential_response,
        )
        credential_id = create_service_specific_credential_response["ServiceSpecificCredential"][
            "ServiceSpecificCredentialId"
        ]

        with pytest.raises(ClientError) as e:
            aws_client.iam.update_service_specific_credential(
                ServiceSpecificCredentialId=credential_id, Status="Invalid"
            )
        snapshot.match("update-invalid-status", e.value.response)


class TestIAMServiceRoles:
    SERVICES = {
        "accountdiscovery.ssm.amazonaws.com": (),
        "acm.amazonaws.com": (),
        "appmesh.amazonaws.com": (),
        "autoscaling-plans.amazonaws.com": (),
        "autoscaling.amazonaws.com": (),
        "backup.amazonaws.com": (),
        "batch.amazonaws.com": (),
        "cassandra.application-autoscaling.amazonaws.com": (),
        "cks.kms.amazonaws.com": (),
        "cloudtrail.amazonaws.com": (),
        "codestar-notifications.amazonaws.com": (),
        "config.amazonaws.com": (),
        "connect.amazonaws.com": (),
        "dms-fleet-advisor.amazonaws.com": (),
        "dms.amazonaws.com": (),
        "docdb-elastic.amazonaws.com": (),
        "ec2-instance-connect.amazonaws.com": (),
        "ec2.application-autoscaling.amazonaws.com": (),
        "ecr.amazonaws.com": (),
        "ecs.amazonaws.com": (),
        "eks-connector.amazonaws.com": (),
        "eks-fargate.amazonaws.com": (),
        "eks-nodegroup.amazonaws.com": (),
        "eks.amazonaws.com": (),
        "elasticache.amazonaws.com": (),
        "elasticbeanstalk.amazonaws.com": (),
        "elasticfilesystem.amazonaws.com": (),
        "elasticloadbalancing.amazonaws.com": (),
        "email.cognito-idp.amazonaws.com": (),
        "emr-containers.amazonaws.com": (),
        "emrwal.amazonaws.com": (),
        "fis.amazonaws.com": (),
        "grafana.amazonaws.com": (),
        "imagebuilder.amazonaws.com": (),
        "iotmanagedintegrations.amazonaws.com": (
            markers.snapshot.skip_snapshot_verify(paths=["$..AttachedPolicies"])
        ),  # TODO include aws managed policy in the future
        "kafka.amazonaws.com": (),
        "kafkaconnect.amazonaws.com": (),
        "lakeformation.amazonaws.com": (),
        "lex.amazonaws.com": (
            markers.snapshot.skip_snapshot_verify(paths=["$..AttachedPolicies"])
        ),  # TODO include aws managed policy in the future
        "lexv2.amazonaws.com": (),
        "lightsail.amazonaws.com": (),
        # "logs.amazonaws.com": (),  # not possible to create on AWS
        "m2.amazonaws.com": (),
        "memorydb.amazonaws.com": (),
        "mq.amazonaws.com": (),
        "mrk.kms.amazonaws.com": (),
        "notifications.amazonaws.com": (),
        "observability.aoss.amazonaws.com": (),
        "opensearchservice.amazonaws.com": (),
        "ops.apigateway.amazonaws.com": (),
        "ops.emr-serverless.amazonaws.com": (),
        "opsdatasync.ssm.amazonaws.com": (),
        "opsinsights.ssm.amazonaws.com": (),
        "pullthroughcache.ecr.amazonaws.com": (),
        "ram.amazonaws.com": (),
        "rds.amazonaws.com": (),
        "redshift.amazonaws.com": (),
        "replication.cassandra.amazonaws.com": (),
        "replication.ecr.amazonaws.com": (),
        "repository.sync.codeconnections.amazonaws.com": (),
        "resource-explorer-2.amazonaws.com": (),
        # "resourcegroups.amazonaws.com": (),  # not possible to create on AWS
        "rolesanywhere.amazonaws.com": (),
        "s3-outposts.amazonaws.com": (),
        "ses.amazonaws.com": (),
        "shield.amazonaws.com": (),
        "ssm-incidents.amazonaws.com": (),
        "ssm-quicksetup.amazonaws.com": (),
        "ssm.amazonaws.com": (),
        "sso.amazonaws.com": (),
        "vpcorigin.cloudfront.amazonaws.com": (),
        "waf.amazonaws.com": (),
        "wafv2.amazonaws.com": (),
    }

    SERVICES_CUSTOM_SUFFIX = [
        "autoscaling.amazonaws.com",
        "connect.amazonaws.com",
        "lexv2.amazonaws.com",
    ]

    @pytest.fixture
    def create_service_linked_role(self, aws_client):
        role_names = []

        @functools.wraps(aws_client.iam.create_service_linked_role)
        def _create_service_linked_role(*args, **kwargs):
            response = aws_client.iam.create_service_linked_role(*args, **kwargs)
            role_names.append(response["Role"]["RoleName"])
            return response

        yield _create_service_linked_role
        for role_name in role_names:
            try:
                aws_client.iam.delete_service_linked_role(RoleName=role_name)
            except Exception as e:
                LOG.debug("Error while deleting service linked role '%s': %s", role_name, e)

    @pytest.fixture
    def create_service_linked_role_if_not_exists(self, aws_client, create_service_linked_role):
        """This fixture is necessary since some service linked roles cannot be deleted - so we have to snapshot the existing ones"""

        def _create_service_linked_role_if_not_exists(*args, **kwargs):
            try:
                return create_service_linked_role(*args, **kwargs)["Role"]["RoleName"]
            except aws_client.iam.exceptions.InvalidInputException as e:
                # return the role name from the error message for now, quite hacky.
                return e.response["Error"]["Message"].split()[3]

        return _create_service_linked_role_if_not_exists

    @pytest.fixture(autouse=True)
    def snapshot_transformers(self, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("RoleId"))

    @markers.aws.validated
    # last used and the description depend on whether the role was created in the snapshot account by a service or manually
    @markers.snapshot.skip_snapshot_verify(paths=["$..Role.RoleLastUsed", "$..Role.Description"])
    @pytest.mark.parametrize(
        "service_name",
        [pytest.param(service, marks=marker) for service, marker in SERVICES.items()],
    )
    def test_service_role_lifecycle(
        self, aws_client, snapshot, create_service_linked_role_if_not_exists, service_name
    ):
        # some roles are already present and not deletable - so we just create them if they exist, and snapshot later
        role_name = create_service_linked_role_if_not_exists(AWSServiceName=service_name)

        response = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("describe-response", response)

        response = aws_client.iam.list_role_policies(RoleName=role_name)
        snapshot.match("inline-role-policies", response)

        response = aws_client.iam.list_attached_role_policies(RoleName=role_name)
        snapshot.match("attached-role-policies", response)

    @markers.aws.validated
    @pytest.mark.parametrize("service_name", SERVICES_CUSTOM_SUFFIX)
    def test_service_role_lifecycle_custom_suffix(
        self, aws_client, snapshot, create_service_linked_role, service_name
    ):
        """Tests services allowing custom suffixes"""
        custom_suffix = short_uid()
        snapshot.add_transformer(snapshot.transform.regex(custom_suffix, "<suffix>"))
        response = create_service_linked_role(
            AWSServiceName=service_name, CustomSuffix=custom_suffix
        )
        role_name = response["Role"]["RoleName"]

        response = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("describe-response", response)

        response = aws_client.iam.list_role_policies(RoleName=role_name)
        snapshot.match("inline-role-policies", response)

        response = aws_client.iam.list_attached_role_policies(RoleName=role_name)
        snapshot.match("attached-role-policies", response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "service_name", list(set(SERVICES.keys()) - set(SERVICES_CUSTOM_SUFFIX))
    )
    def test_service_role_lifecycle_custom_suffix_not_allowed(
        self, aws_client, snapshot, create_service_linked_role, service_name
    ):
        """Test services which do not allow custom suffixes"""
        suffix = "testsuffix"
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_service_linked_role(
                AWSServiceName=service_name, CustomSuffix=suffix
            )
        snapshot.match("custom-suffix-not-allowed", e.value.response)

    @markers.aws.validated
    def test_service_role_deletion(self, aws_client, snapshot, create_service_linked_role):
        """Testing deletion only with one service name to avoid undeletable service linked roles in developer accounts"""
        snapshot.add_transformer(snapshot.transform.regex(PATTERN_UUID, "<uuid>"))
        service_name = "batch.amazonaws.com"
        role_name = create_service_linked_role(AWSServiceName=service_name)["Role"]["RoleName"]

        response = aws_client.iam.delete_service_linked_role(RoleName=role_name)
        snapshot.match("service-linked-role-deletion-response", response)
        deletion_task_id = response["DeletionTaskId"]

        def wait_role_deleted():
            response = aws_client.iam.get_service_linked_role_deletion_status(
                DeletionTaskId=deletion_task_id
            )
            assert response["Status"] == "SUCCEEDED"
            return response

        response = retry(wait_role_deleted, retries=10, sleep=1)
        snapshot.match("service-linked-role-deletion-status-response", response)

    @markers.aws.validated
    def test_service_role_already_exists(self, aws_client, snapshot, create_service_linked_role):
        service_name = "batch.amazonaws.com"
        create_service_linked_role(AWSServiceName=service_name)

        with pytest.raises(ClientError) as e:
            aws_client.iam.create_service_linked_role(AWSServiceName=service_name)
        snapshot.match("role-already-exists-error", e.value.response)
