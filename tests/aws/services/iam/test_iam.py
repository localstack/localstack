import json
from urllib.parse import quote_plus

import pytest
from botocore.exceptions import ClientError

from localstack.aws.api.iam import Tag
from localstack.services.iam.provider import ADDITIONAL_MANAGED_POLICIES
from localstack.testing.aws.util import create_client_with_keys, wait_for_user
from localstack.testing.pytest import markers
from localstack.utils.aws.arns import get_partition
from localstack.utils.common import short_uid
from localstack.utils.strings import long_uid

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
    def test_delete_non_existent_policy_returns_no_such_entity(self, aws_client):
        non_existent_policy_arn = "arn:aws:iam::000000000000:policy/non-existent-policy"

        with pytest.raises(ClientError) as ctx:
            aws_client.iam.delete_policy(PolicyArn=non_existent_policy_arn)
        assert ctx.typename == "NoSuchEntityException"
        assert ctx.value.response["Error"]["Code"] == "NoSuchEntity"

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

    @markers.aws.needs_fixing
    def test_simulate_principle_policy(self, aws_client):
        # FIXME this test should test whether a principal (like user, role) has some permissions, it cannot test
        # the policy itself
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

        policy_arn = aws_client.iam.create_policy(
            PolicyName=policy_name, Path="/", PolicyDocument=json.dumps(policy_document)
        )["Policy"]["Arn"]

        rs = aws_client.iam.simulate_principal_policy(
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
        create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume_policy_document))

        aws_client.iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document)
        )
        get_policy_response = aws_client.iam.get_role_policy(
            RoleName=role_name, PolicyName=policy_name
        )
        snapshot.match("get-policy-response", get_policy_response)

        get_role_response = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-response", get_role_response)

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
