import json
import logging
import os
import uuid
from datetime import datetime
from math import isclose
from typing import Optional

import pytest
import requests
from botocore.auth import SigV4Auth

from localstack.aws.api.lambda_ import Runtime
from localstack.aws.api.secretsmanager import (
    CreateSecretRequest,
    CreateSecretResponse,
    DeleteSecretRequest,
    DeleteSecretResponse,
    ListSecretsResponse,
)
from localstack.constants import TEST_AWS_ACCESS_KEY_ID, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer import SortingTransformer
from localstack.utils.aws import aws_stack
from localstack.utils.aws.request_context import mock_aws_request_headers
from localstack.utils.collections import select_from_typed_dict
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition
from localstack.utils.time import today_no_time

LOG = logging.getLogger(__name__)


RESOURCE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{TEST_AWS_ACCOUNT_ID}:root"},
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "*",
        }
    ],
}

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_ROTATE_SECRET = os.path.join(THIS_FOLDER, "functions", "lambda_rotate_secret.py")


class TestSecretsManager:
    @pytest.fixture
    def secret_name(self, aws_client, cleanups) -> str:
        """
        Returns a new unique SecretId, and schedules its deletion though the cleanups mechanism.
        :return: a new and automatically deleted unique SecretId.
        """
        secret_name = f"s-{short_uid()}"
        cleanups.append(
            lambda: aws_client.secretsmanager.delete_secret(
                SecretId=secret_name, ForceDeleteWithoutRecovery=True
            )
        )
        return secret_name

    @pytest.fixture
    def sm_snapshot(self, snapshot):
        snapshot.add_transformers_list(snapshot.transform.secretsmanager_api())
        return snapshot

    @staticmethod
    def _wait_created_is_listed(client, secret_id: str):
        def _is_secret_in_list():
            lst: ListSecretsResponse = client.list_secrets()
            secret_ids: set[str] = {secret["Name"] for secret in lst.get("SecretList", [])}
            return secret_id in secret_ids

        success = poll_condition(condition=_is_secret_in_list, timeout=20, interval=2)
        if not success:
            LOG.warning(f"Timed out whilst awaiting for secret '{secret_id}' to become listable.")

    @staticmethod
    def _wait_force_deletion_completed(client, secret_id: str):
        def _is_secret_deleted():
            deleted = False
            try:
                client.describe_secret(SecretId=secret_id)
            except Exception as ex:
                if ex.response["Error"]["Code"] == "ResourceNotFoundException":
                    deleted = True
                else:
                    raise ex
            return deleted

        success = poll_condition(condition=_is_secret_deleted, timeout=120, interval=30)
        if not success:
            LOG.warning(
                f"Timed out whilst awaiting for force deletion of secret '{secret_id}' to complete."
            )

    @staticmethod
    def _wait_rotation(client, secret_id: str, secret_version: str):
        def _is_secret_rotated():
            resp: dict = client.describe_secret(SecretId=secret_id)
            secret_stage_tags = list()
            for key, tags in resp.get("VersionIdsToStages", {}).items():
                if key == secret_version:
                    secret_stage_tags = tags
                    break
            return "AWSCURRENT" in secret_stage_tags

        success = poll_condition(condition=_is_secret_rotated, timeout=120, interval=5)
        if not success:
            LOG.warning(
                f"Timed out whilst awaiting for secret '{secret_id}' to be rotated to new version."
            )

    @pytest.mark.parametrize(
        "secret_name",
        [
            "s-c64bdc03",
            "Valid/_+=.@-Name",
            "Valid/_+=.@-Name-a1b2",
            "Valid/_+=.@-Name-a1b2c3-",
        ],
    )
    @markers.aws.unknown
    def test_create_and_update_secret(self, secret_name: str, sm_snapshot, cleanups, aws_client):
        cleanups.append(
            lambda: aws_client.secretsmanager.delete_secret(
                SecretId=secret_name, ForceDeleteWithoutRecovery=True
            )
        )
        description = "Testing secret creation."
        create_secret_rs_1 = aws_client.secretsmanager.create_secret(
            Name=secret_name,
            SecretString="my_secret",
            Description=description,
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_1, 0)
        )
        sm_snapshot.match("create_secret_rs_1", create_secret_rs_1)
        #
        secret_arn = create_secret_rs_1["ARN"]
        assert len(secret_arn.rpartition("-")[-1]) == 6

        get_secret_value_rs_1 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_rs_1", get_secret_value_rs_1)

        describe_secret_rs_1 = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
        sm_snapshot.match("describe_secret_rs_1", describe_secret_rs_1)

        get_secret_value_rs_2 = aws_client.secretsmanager.get_secret_value(SecretId=secret_arn)
        sm_snapshot.match("get_secret_value_rs_2", get_secret_value_rs_2)

        # Ensure retrieval with partial ARN works
        get_secret_value_rs_3 = aws_client.secretsmanager.get_secret_value(SecretId=secret_arn[:-7])
        sm_snapshot.match("get_secret_value_rs_3", get_secret_value_rs_3)

        put_secret_value_rs_1 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString="new_secret"
        )
        sm_snapshot.match("put_secret_value_rs_1", put_secret_value_rs_1)

        get_secret_value_rs_4 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_rs_4", get_secret_value_rs_4)

        # update secret by ARN
        update_secret_res_1 = aws_client.secretsmanager.update_secret(
            SecretId=secret_arn, SecretString="test123", Description="d1"
        )
        sm_snapshot.match("update_secret_res_1", update_secret_res_1)

        # clean up
        delete_secret_res_1 = aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )
        sm_snapshot.match("delete_secret_res_1", delete_secret_res_1)

    @markers.aws.unknown
    def test_secret_not_found(self, sm_snapshot, aws_client):
        with pytest.raises(Exception) as not_found:
            aws_client.secretsmanager.get_secret_value(SecretId=f"s-{short_uid()}")
        sm_snapshot.match("get_secret_value_not_found_ex", not_found.value.response)

        with pytest.raises(Exception) as not_found:
            aws_client.secretsmanager.list_secret_version_ids(SecretId=f"s-{short_uid()}")
        sm_snapshot.match("list_secret_version_ids_not_found_ex", not_found.value.response)

    @markers.aws.unknown
    def test_call_lists_secrets_multiple_times(self, secret_name, aws_client):
        aws_client.secretsmanager.create_secret(
            Name=secret_name,
            SecretString="my_secret",
            Description="testing creation of secrets",
        )
        self._wait_created_is_listed(aws_client.secretsmanager, secret_id=secret_name)

        # call list_secrets multiple times
        for i in range(3):
            rs = aws_client.secretsmanager.list_secrets()
            secrets = [secret for secret in rs["SecretList"] if secret["Name"] == secret_name]
            assert len(secrets) == 1

        # clean up
        aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )

    @pytest.mark.skip("In CI transformers are not applied for this test.")
    @markers.aws.unknown
    def test_call_lists_secrets_multiple_times_snapshots(
        self, sm_snapshot, secret_name, aws_client
    ):
        create_secret_rs_1 = aws_client.secretsmanager.create_secret(
            Name=secret_name,
            SecretString="my_secret",
            Description="testing creation of secrets",
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_1, 0)
        )
        sm_snapshot.match("create_secret_rs_1", create_secret_rs_1)

        self._wait_created_is_listed(aws_client.secretsmanager, secret_id=secret_name)

        # call list_secrets multiple times
        for i in range(3):
            list_secrets_res = aws_client.secretsmanager.list_secrets()
            sm_snapshot.match(f"list_secrets_res_{i}", list_secrets_res)

        # clean up
        delete_secret_res_1 = aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )
        sm_snapshot.match("delete_secret_res_1", delete_secret_res_1)

    @markers.aws.unknown
    def test_create_multi_secrets(self, cleanups, aws_client):
        secret_names = [short_uid(), short_uid(), short_uid()]
        arns = []
        for secret_name in secret_names:
            cleanups.append(
                lambda: aws_client.secretsmanager.delete_secret(
                    SecretId=secret_name, ForceDeleteWithoutRecovery=True
                )
            )
            rs = aws_client.secretsmanager.create_secret(
                Name=secret_name,
                SecretString="my_secret_{}".format(secret_name),
                Description="testing creation of secrets",
            )
            arns.append(rs["ARN"])
            self._wait_created_is_listed(aws_client.secretsmanager, secret_id=secret_name)

        rs = aws_client.secretsmanager.list_secrets()
        secrets = {
            secret["Name"]: secret["ARN"]
            for secret in rs["SecretList"]
            if secret["Name"] in secret_names
        }

        assert len(secrets.keys()) == len(secret_names)
        for arn in arns:
            assert arn in secrets.values()

        # clean up
        for secret_name in secret_names:
            aws_client.secretsmanager.delete_secret(
                SecretId=secret_name, ForceDeleteWithoutRecovery=True
            )

    @pytest.mark.skip("In CI transformers are not applied for this test.")
    @markers.aws.unknown
    def test_create_multi_secrets_snapshot(self, sm_snapshot, cleanups, aws_client):
        secret_names = [short_uid() for _ in range(3)]
        for i, secret_name in enumerate(secret_names):
            cleanups.append(
                lambda: aws_client.secretsmanager.delete_secret(
                    SecretId=secret_name, ForceDeleteWithoutRecovery=True
                )
            )
            create_secret_rs_1 = aws_client.secretsmanager.create_secret(
                Name=secret_name,
                SecretString=f"my_secret_{secret_name}",
                Description="Testing secrets creation.",
            )
            sm_snapshot.add_transformers_list(
                sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_1, i)
            )

            self._wait_created_is_listed(aws_client.secretsmanager, secret_name)

        list_secrets_res = aws_client.secretsmanager.list_secrets()
        sm_snapshot.match("list_secrets_res", list_secrets_res)

        # clean up
        for i, secret_name in enumerate(secret_names):
            delete_secret_res = aws_client.secretsmanager.delete_secret(
                SecretId=secret_name, ForceDeleteWithoutRecovery=True
            )
            sm_snapshot.match(f"delete_secret_res{i}", delete_secret_res)

    @markers.aws.unknown
    def test_get_random_exclude_characters_and_symbols(self, aws_client):
        random_password = aws_client.secretsmanager.get_random_password(
            PasswordLength=120, ExcludeCharacters="xyzDje@?!."
        )

        assert len(random_password["RandomPassword"]) == 120
        assert all(c not in "xyzDje@?!." for c in random_password["RandomPassword"])

    @markers.aws.unknown
    def test_resource_policy(self, secret_name, aws_client):
        aws_client.secretsmanager.create_secret(
            Name=secret_name,
            SecretString="my_secret",
            Description="testing creation of secrets",
        )

        aws_client.secretsmanager.put_resource_policy(
            SecretId=secret_name, ResourcePolicy=json.dumps(RESOURCE_POLICY)
        )

        rs = aws_client.secretsmanager.get_resource_policy(SecretId=secret_name)

        policy = json.loads(rs["ResourcePolicy"])

        assert policy["Version"] == RESOURCE_POLICY["Version"]
        assert policy["Statement"] == RESOURCE_POLICY["Statement"]

        rs = aws_client.secretsmanager.delete_resource_policy(SecretId=secret_name)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        # clean up
        aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )

    @markers.snapshot.skip_snapshot_verify(paths=["$..Versions..KmsKeyIds"])
    @markers.aws.validated
    def test_rotate_secret_with_lambda_success(
        self, sm_snapshot, secret_name, create_secret, create_lambda_function, aws_client
    ):
        cre_res = create_secret(
            Name=secret_name,
            SecretString="my_secret",
            Description="testing rotation of secrets",
        )

        sm_snapshot.add_transformer(SortingTransformer("Versions", lambda x: x["CreatedDate"]))
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(cre_res, 0)
        )

        function_name = f"s-{short_uid()}"
        function_arn = create_lambda_function(
            handler_file=TEST_LAMBDA_ROTATE_SECRET,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )["CreateFunctionResponse"]["FunctionArn"]

        aws_client.lambda_.add_permission(
            FunctionName=function_name,
            StatementId="secretsManagerPermission",
            Action="lambda:InvokeFunction",
            Principal="secretsmanager.amazonaws.com",
        )

        rot_res = aws_client.secretsmanager.rotate_secret(
            SecretId=secret_name,
            RotationLambdaARN=function_arn,
            RotationRules={
                "AutomaticallyAfterDays": 1,
            },
            RotateImmediately=True,
        )

        sm_snapshot.match("rotate_secret_immediately", rot_res)

        self._wait_rotation(aws_client.secretsmanager, secret_name, rot_res["VersionId"])

        list_secret_versions_1 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )

        sm_snapshot.match("list_secret_versions_rotated_1", list_secret_versions_1)

    @markers.aws.unknown
    def test_rotate_secret_invalid_lambda_arn(self, secret_name, aws_client):
        aws_client.secretsmanager.create_secret(Name=secret_name, SecretString="init")
        invalid_arn = (
            "arn:aws:lambda:sa-east-1:000000000000:function:rotate_secret_invalid_lambda_arn"
        )
        with pytest.raises(Exception) as res_not_found_ex:
            aws_client.secretsmanager.rotate_secret(
                SecretId=secret_name,
                RotationLambdaARN=invalid_arn,
                RotationRules={
                    "AutomaticallyAfterDays": 1,
                },
            )
        assert res_not_found_ex.typename == "ResourceNotFoundException"
        assert (
            res_not_found_ex.value.response["Error"]["Message"]
            == "Lambda does not exist or could not be accessed"
        )

        des = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
        assert "RotationEnabled" not in des
        assert "RotationRules" not in des
        assert "RotationLambdaARN" not in des

    @markers.aws.unknown
    def test_put_secret_value_with_version_stages(self, sm_snapshot, secret_name, aws_client):
        secret_string_v0: str = "secret_string_v0"

        create_secret_rs_0 = aws_client.secretsmanager.create_secret(
            Name=secret_name, SecretString=secret_string_v0
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_0, 0)
        )
        sm_snapshot.match("create_secret_rs_0", create_secret_rs_0)

        get_secret_value_res_0 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_0", get_secret_value_res_0)

        secret_string_v1: str = "secret_string_v1"
        version_stages_v1: list[str] = ["SAMPLESTAGE1", "SAMPLESTAGE0"]
        pv_v1_vid: str = str(uuid.uuid4())
        #
        put_secret_value_res_1 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name,
            SecretString=secret_string_v1,
            VersionStages=version_stages_v1,
            ClientRequestToken=pv_v1_vid,
        )
        sm_snapshot.match("put_secret_value_res_1", put_secret_value_res_1)

        get_secret_value_res_1 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_1", get_secret_value_res_1)

        secret_string_v2: str = "secret_string_v2"
        version_stages_v2: list[str] = version_stages_v1
        pv_v2_vid: str = str(uuid.uuid4())
        #
        put_secret_value_res_2 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name,
            SecretString=secret_string_v2,
            VersionStages=version_stages_v2,
            ClientRequestToken=pv_v2_vid,
        )
        sm_snapshot.match("put_secret_value_res_2", put_secret_value_res_2)

        get_secret_value_res_2 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_2", get_secret_value_res_2)

        secret_string_v3: str = "secret_string_v3"
        version_stages_v3: ["str"] = ["AWSPENDING"]
        pv_v3_vid: str = str(uuid.uuid4())
        #
        put_secret_value_res_3 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name,
            SecretString=secret_string_v3,
            VersionStages=version_stages_v3,
            ClientRequestToken=pv_v3_vid,
        )
        sm_snapshot.match("put_secret_value_res_3", put_secret_value_res_3)

        get_secret_value_res_3 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_3", get_secret_value_res_3)

        secret_string_v4: str = "secret_string_v4"
        pv_v4_vid: str = str(uuid.uuid4())
        #
        put_secret_value_res_4 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString=secret_string_v4, ClientRequestToken=pv_v4_vid
        )
        sm_snapshot.match("put_secret_value_res_4", put_secret_value_res_4)

        get_secret_value_res_4 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_4", get_secret_value_res_4)

        delete_secret_res_1 = aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )
        sm_snapshot.match("delete_secret_res_1", delete_secret_res_1)

    @pytest.mark.parametrize(
        "secret_name", ["Inv Name", " Inv Name", " Inv*Name? ", " Inv *?!]Name\\-"]
    )
    @markers.aws.validated
    def test_invalid_secret_name(self, sm_snapshot, cleanups, secret_name: str, aws_client):
        cleanups.append(
            lambda: aws_client.secretsmanager.delete_secret(
                SecretId=secret_name, ForceDeleteWithoutRecovery=True
            )
        )
        # The secret name can contain ASCII letters, numbers, and the following characters: /_+=.@-
        with pytest.raises(Exception) as validation_exception:
            aws_client.secretsmanager.create_secret(Name=secret_name, SecretString="MySecretString")
        sm_snapshot.match("ex_log_1", validation_exception.value.response)

        with pytest.raises(Exception) as validation_exception:
            aws_client.secretsmanager.delete_secret(
                SecretId=secret_name, ForceDeleteWithoutRecovery=True
            )
        sm_snapshot.match("ex_log_2", validation_exception.value.response)

        with pytest.raises(Exception) as validation_exception:
            aws_client.secretsmanager.describe_secret(SecretId=secret_name)
        sm_snapshot.match("ex_log_3", validation_exception.value.response)

        with pytest.raises(Exception) as validation_exception:
            aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("ex_log_4", validation_exception.value.response)

        with pytest.raises(Exception) as validation_exception:
            aws_client.secretsmanager.list_secret_version_ids(
                SecretId=secret_name, IncludeDeprecated=True
            )
        sm_snapshot.match("ex_log_5", validation_exception.value.response)

        with pytest.raises(Exception) as validation_exception:
            aws_client.secretsmanager.put_secret_value(
                SecretId=secret_name, SecretString="MySecretString"
            )
        sm_snapshot.match("ex_log_6", validation_exception.value.response)

        with pytest.raises(Exception) as validation_exception:
            aws_client.secretsmanager.tag_resource(
                SecretId=secret_name, Tags=[{"Key": "FirstTag", "Value": "SomeValue"}]
            )
        sm_snapshot.match("ex_log_7", validation_exception.value.response)

        with pytest.raises(Exception) as validation_exception:
            aws_client.secretsmanager.untag_resource(SecretId=secret_name, TagKeys=["FirstTag"])
        sm_snapshot.match("ex_log_8", validation_exception.value.response)

        with pytest.raises(Exception) as validation_exception:
            aws_client.secretsmanager.update_secret(
                SecretId=secret_name, Description="MyNewDescription"
            )
        sm_snapshot.match("ex_log_9", validation_exception.value.response)

        with pytest.raises(Exception) as validation_exception:
            aws_client.secretsmanager.validate_resource_policy(
                SecretId=secret_name,
                ResourcePolicy='{\n"Version":"2012-10-17",\n"Statement":[{\n"Effect":"Allow",\n"Principal":{\n"AWS":"arn:aws:iam::123456789012:root"\n},\n"Action":"secretsmanager:GetSecretValue",\n"Resource":"*"\n}]\n}',
            )
        sm_snapshot.match("ex_log_10", validation_exception.value.response)

    @markers.aws.unknown
    def test_last_accessed_date(self, cleanups, aws_client):
        def last_accessed_scenario_1(fail_if_days_overlap: bool) -> bool:
            secret_name = f"s-{short_uid()}"
            cleanups.append(
                lambda: aws_client.secretsmanager.delete_secret(
                    SecretId=secret_name, ForceDeleteWithoutRecovery=True
                )
            )

            aws_client.secretsmanager.create_secret(Name=secret_name, SecretString="MySecretValue")

            des = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
            assert "LastAccessedDate" not in des

            t0 = today_no_time()

            aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
            des = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
            assert "LastAccessedDate" in des
            lad_v0 = des["LastAccessedDate"]
            assert isinstance(lad_v0, datetime)

            aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
            des = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
            assert "LastAccessedDate" in des
            lad_v1 = des["LastAccessedDate"]
            assert isinstance(lad_v1, datetime)

            if t0 == today_no_time() or fail_if_days_overlap:
                assert lad_v0 == lad_v1
                return True
            else:
                return False

        if not last_accessed_scenario_1(
            False
        ):  # Test started yesterday and ended today (where relevant).
            last_accessed_scenario_1(
                True
            )  # Replay today or allow failure (this should never take longer than a day).

    @markers.aws.unknown
    def test_last_updated_date(self, secret_name, aws_client):
        # TODO: moto is rounding time.time() but `secretsmanager`return a timestamp with 3 fraction digits
        # adapt the tests for around equality
        aws_client.secretsmanager.create_secret(Name=secret_name, SecretString="MySecretValue")

        res = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
        assert "LastChangedDate" in res
        create_date = res["LastChangedDate"]
        assert isinstance(create_date, datetime)
        create_date_ts = create_date.timestamp()

        res = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        assert isclose(create_date_ts, res["CreatedDate"].timestamp(), rel_tol=1)

        res = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
        assert "LastChangedDate" in res
        assert isclose(create_date_ts, res["LastChangedDate"].timestamp(), rel_tol=1)

        aws_client.secretsmanager.update_secret(
            SecretId=secret_name, SecretString="MyNewSecretValue"
        )

        res = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
        assert "LastChangedDate" in res
        assert create_date < res["LastChangedDate"]
        last_changed = res["LastChangedDate"]

        aws_client.secretsmanager.update_secret(
            SecretId=secret_name, SecretString="MyNewSecretValue"
        )

        res = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
        assert "LastChangedDate" in res
        assert last_changed < res["LastChangedDate"]

        aws_client.secretsmanager.update_secret(
            SecretId=secret_name, SecretString="MyVeryNewSecretValue"
        )

        res = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
        assert "LastChangedDate" in res
        assert create_date < res["LastChangedDate"]

    @markers.aws.unknown
    def test_update_secret_description(self, sm_snapshot, secret_name, aws_client):
        secret_string_v0 = "MySecretString"
        create_secret_rs_0 = aws_client.secretsmanager.create_secret(
            Name=secret_name, SecretString=secret_string_v0
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_0, 0)
        )
        sm_snapshot.match("create_secret_rs_0", create_secret_rs_0)

        describe_secret_res_0 = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
        sm_snapshot.match("describe_secret_res_0", describe_secret_res_0)

        description_v1 = "MyDescription"
        #
        update_secret_res_0 = aws_client.secretsmanager.update_secret(
            SecretId=secret_name, Description=description_v1
        )
        sm_snapshot.match("update_secret_res_0", update_secret_res_0)

        describe_secret_res_1 = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
        sm_snapshot.match("describe_secret_res_1", describe_secret_res_1)

        description_v2 = "MyNewDescription"
        secret_string_v1 = "MyNewSecretString"
        #
        update_secret_res_1 = aws_client.secretsmanager.update_secret(
            SecretId=secret_name, SecretString=secret_string_v1, Description=description_v2
        )
        sm_snapshot.match("update_secret_res_1", update_secret_res_1)

        describe_secret_res_2 = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
        sm_snapshot.match("describe_secret_res_2", describe_secret_res_2)

        update_secret_res_2 = aws_client.secretsmanager.update_secret(
            SecretId=secret_name, SecretString=secret_string_v1 * 2
        )
        sm_snapshot.match("update_secret_res_2", update_secret_res_2)

        describe_secret_res_3 = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
        sm_snapshot.match("describe_secret_res_3", describe_secret_res_3)

        update_secret_res_3 = aws_client.secretsmanager.update_secret(SecretId=secret_name)
        sm_snapshot.match("update_secret_res_3", update_secret_res_3)

        describe_secret_res_4 = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
        sm_snapshot.match("describe_secret_res_4", describe_secret_res_4)

        delete_secret_res_0 = aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )
        sm_snapshot.match("delete_secret_res_0", delete_secret_res_0)

    @markers.aws.unknown
    def test_update_secret_version_stages_return_type(self, sm_snapshot, secret_name, aws_client):
        create_secret_rs_0 = aws_client.secretsmanager.create_secret(
            Name=secret_name, SecretString="Something1"
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_0, 0)
        )
        sm_snapshot.match("create_secret_rs_0", create_secret_rs_0)

        version_id_v0: str = create_secret_rs_0["VersionId"]

        put_secret_value_res_0 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString="Something2", VersionStages=["AWSPENDING"]
        )
        sm_snapshot.match("put_secret_value_res_0", put_secret_value_res_0)

        version_id_v1 = put_secret_value_res_0["VersionId"]
        assert version_id_v1 != version_id_v0

        update_secret_version_stage_res_0 = aws_client.secretsmanager.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=version_id_v0,
            MoveToVersionId=version_id_v1,
            VersionStage="AWSCURRENT",
        )
        sm_snapshot.match("update_secret_version_stage_res_0", update_secret_version_stage_res_0)

        delete_secret_res_0 = aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )
        sm_snapshot.match("delete_secret_res_0", delete_secret_res_0)

    @markers.snapshot.skip_snapshot_verify(paths=["$..KmsKeyId", "$..KmsKeyIds"])
    @markers.aws.unknown
    def test_update_secret_version_stages_current_previous(
        self, sm_snapshot, secret_name, aws_client
    ):
        secret_string_v0 = "secret_string_v0"
        create_secret_rs_0 = aws_client.secretsmanager.create_secret(
            Name=secret_name, SecretString=secret_string_v0
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_0, 0)
        )
        sm_snapshot.match("create_secret_rs_0", create_secret_rs_0)

        self._wait_created_is_listed(aws_client.secretsmanager, secret_name)

        list_secret_version_ids_res_0 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_0", list_secret_version_ids_res_0)

        secret_string_v1 = "secret_string_v1"
        #
        update_secret_res_0 = aws_client.secretsmanager.update_secret(
            SecretId=secret_name, SecretString=secret_string_v1
        )
        sm_snapshot.match("update_secret_res_0", update_secret_res_0)

        list_secret_version_ids_res_1 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_1", list_secret_version_ids_res_1)

        delete_secret_res_0 = aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )
        sm_snapshot.match("delete_secret_res_0", delete_secret_res_0)

    @markers.snapshot.skip_snapshot_verify(paths=["$..KmsKeyId", "$..KmsKeyIds"])
    @markers.aws.unknown
    def test_update_secret_version_stages_current_pending(
        self, sm_snapshot, secret_name, aws_client
    ):
        create_secret_rs_0 = aws_client.secretsmanager.create_secret(
            Name=secret_name, SecretString="Something1"
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_0, 0)
        )
        sm_snapshot.match("create_secret_rs_0", create_secret_rs_0)

        version_id_v0 = create_secret_rs_0["VersionId"]

        put_secret_value_res_0 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString="Something2", VersionStages=["AWSPENDING"]
        )
        sm_snapshot.match("put_secret_value_res_0", put_secret_value_res_0)

        version_id_v1 = put_secret_value_res_0["VersionId"]

        list_secret_version_ids_res_0 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_0", list_secret_version_ids_res_0)

        update_secret_version_stage_res_0 = aws_client.secretsmanager.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=version_id_v0,
            MoveToVersionId=version_id_v1,
            VersionStage="AWSCURRENT",
        )
        sm_snapshot.match("update_secret_version_stage_res_0", update_secret_version_stage_res_0)

        list_secret_version_ids_res_1 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_1", list_secret_version_ids_res_1)

        put_secret_value_res_1 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString="SS3"
        )
        sm_snapshot.match("put_secret_value_res_1", put_secret_value_res_1)

        list_secret_version_ids_res_2 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_2", list_secret_version_ids_res_2)

        delete_secret_res_0 = aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )
        sm_snapshot.match("delete_secret_res_0", delete_secret_res_0)

    @markers.snapshot.skip_snapshot_verify(paths=["$..KmsKeyId", "$..KmsKeyIds"])
    @markers.aws.unknown
    def test_update_secret_version_stages_current_pending_cycle(
        self, sm_snapshot, secret_name, aws_client
    ):
        create_secret_rs_0 = aws_client.secretsmanager.create_secret(
            Name=secret_name, SecretString="S1"
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_0, 0)
        )
        sm_snapshot.match("create_secret_rs_0", create_secret_rs_0)

        vid_0 = create_secret_rs_0["VersionId"]

        put_secret_value_res_0 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString="S2", VersionStages=["AWSPENDING"]
        )
        sm_snapshot.match("put_secret_value_res_0", put_secret_value_res_0)

        vid_1 = put_secret_value_res_0["VersionId"]

        list_secret_version_ids_res_0 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_0", list_secret_version_ids_res_0)

        get_secret_value_res_0 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_0", get_secret_value_res_0)

        update_secret_version_stage_res_0 = aws_client.secretsmanager.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=vid_0,
            MoveToVersionId=vid_1,
            VersionStage="AWSCURRENT",
        )
        sm_snapshot.match("update_secret_version_stage_res_0", update_secret_version_stage_res_0)

        list_secret_version_ids_res_1 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_1", list_secret_version_ids_res_1)

        get_secret_value_res_1 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_1", get_secret_value_res_1)

        put_secret_value_res_1 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString="S3", VersionStages=["AWSPENDING"]
        )
        sm_snapshot.match("put_secret_value_res_1", put_secret_value_res_1)

        vid_2 = put_secret_value_res_1["VersionId"]

        list_secret_version_ids_res_2 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_2", list_secret_version_ids_res_2)

        get_secret_value_res_2 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_2", get_secret_value_res_2)

        put_secret_value_res_2 = aws_client.secretsmanager.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=vid_1,
            MoveToVersionId=vid_2,
            VersionStage="AWSCURRENT",
        )
        sm_snapshot.match("put_secret_value_res_2", put_secret_value_res_2)

        list_secret_version_ids_res_3 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_3", list_secret_version_ids_res_3)

        get_secret_value_res_3 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_3", get_secret_value_res_3)

        delete_secret_res_0 = aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )
        sm_snapshot.match("delete_secret_res_0", delete_secret_res_0)

    @markers.snapshot.skip_snapshot_verify(paths=["$..KmsKeyId", "$..KmsKeyIds"])
    @markers.aws.unknown
    def test_update_secret_version_stages_current_pending_cycle_custom_stages_1(
        self, sm_snapshot, secret_name, aws_client
    ):
        create_secret_rs_0 = aws_client.secretsmanager.create_secret(
            Name=secret_name, SecretString="S1"
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_0, 0)
        )
        sm_snapshot.match("create_secret_rs_0", create_secret_rs_0)
        vid_0 = create_secret_rs_0["VersionId"]

        put_secret_value_res_0 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name,
            SecretString="S2",
            VersionStages=["AWSSOMETHING", "AWSPENDING", "PUT1"],
        )
        sm_snapshot.match("put_secret_value_res_0", put_secret_value_res_0)
        vid_1 = put_secret_value_res_0["VersionId"]

        list_secret_version_ids_res_0 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_0", list_secret_version_ids_res_0)

        get_secret_value_res_0 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_0", get_secret_value_res_0)

        update_secret_version_stage_res_0 = aws_client.secretsmanager.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=vid_0,
            MoveToVersionId=vid_1,
            VersionStage="AWSCURRENT",
        )
        sm_snapshot.match("update_secret_version_stage_res_0", update_secret_version_stage_res_0)

        list_secret_version_ids_res_1 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_1", list_secret_version_ids_res_1)

        get_secret_value_res_1 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_1", get_secret_value_res_1)

        put_secret_value_res_1 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString="S3", VersionStages=["AWSPENDING", "PUT2"]
        )
        sm_snapshot.match("put_secret_value_res_1", put_secret_value_res_1)
        vid_2 = put_secret_value_res_1["VersionId"]

        list_secret_version_ids_res_2 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_2", list_secret_version_ids_res_2)

        get_secret_value_res_2 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_2", get_secret_value_res_2)

        update_secret_version_stage_res_1 = aws_client.secretsmanager.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=vid_1,
            MoveToVersionId=vid_2,
            VersionStage="AWSCURRENT",
        )
        sm_snapshot.match("update_secret_version_stage_res_1", update_secret_version_stage_res_1)

        list_secret_version_ids_res_3 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_3", list_secret_version_ids_res_3)

        get_secret_value_res_3 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_3", get_secret_value_res_3)

        delete_secret_res_0 = aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )
        sm_snapshot.match("delete_secret_res_0", delete_secret_res_0)

    @markers.snapshot.skip_snapshot_verify(paths=["$..KmsKeyId", "$..KmsKeyIds"])
    @markers.aws.unknown
    def test_update_secret_version_stages_current_pending_cycle_custom_stages_2(
        self, sm_snapshot, secret_name, aws_client
    ):
        create_secret_rs_0 = aws_client.secretsmanager.create_secret(
            Name=secret_name, SecretString="SS"
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_0, 0)
        )
        sm_snapshot.match("create_secret_rs_0", create_secret_rs_0)

        put_secret_value_res_0 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString="S1", VersionStages=["AWSCURRENT", "PUT0"]
        )
        sm_snapshot.match("put_secret_value_res_0", put_secret_value_res_0)
        #
        vid_0 = put_secret_value_res_0["VersionId"]

        list_secret_version_ids_res_0 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_0", list_secret_version_ids_res_0)

        put_secret_value_res_1 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString="S2", VersionStages=["AWSPENDING", "PUT1"]
        )
        sm_snapshot.match("put_secret_value_res_1", put_secret_value_res_1)
        #
        vid_1 = put_secret_value_res_1["VersionId"]

        list_secret_version_ids_res_1 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_1", list_secret_version_ids_res_1)

        get_secret_value_res_0 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_0", get_secret_value_res_0)

        update_secret_version_stage_res_0 = aws_client.secretsmanager.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=vid_0,
            MoveToVersionId=vid_1,
            VersionStage="AWSCURRENT",
        )
        sm_snapshot.match("update_secret_version_stage_res_0", update_secret_version_stage_res_0)

        list_secret_version_ids_res_2 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_2", list_secret_version_ids_res_2)

        get_secret_value_res_1 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_1", get_secret_value_res_1)

        put_secret_value_res_2 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString="S3", VersionStages=["AWSPENDING", "PUT2"]
        )
        sm_snapshot.match("put_secret_value_res_2", put_secret_value_res_2)
        #
        vid_2 = put_secret_value_res_2["VersionId"]

        list_secret_version_ids_res_3 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_3", list_secret_version_ids_res_3)

        get_secret_value_res_2 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_2", get_secret_value_res_2)

        update_secret_version_stage_res_1 = aws_client.secretsmanager.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=vid_1,
            MoveToVersionId=vid_2,
            VersionStage="AWSCURRENT",
        )
        sm_snapshot.match("update_secret_version_stage_res_1", update_secret_version_stage_res_1)

        list_secret_version_ids_res_4 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_4", list_secret_version_ids_res_4)

        get_secret_value_res_3 = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)
        sm_snapshot.match("get_secret_value_res_3", get_secret_value_res_3)

        delete_secret_res_0 = aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )
        sm_snapshot.match("delete_secret_res_0", delete_secret_res_0)

    @markers.snapshot.skip_snapshot_verify(paths=["$..KmsKeyId", "$..KmsKeyIds"])
    @markers.aws.unknown
    def test_non_versioning_version_stages_replacement(self, sm_snapshot, secret_name, aws_client):
        create_secret_rs_0 = aws_client.secretsmanager.create_secret(
            Name=secret_name, SecretString="S0"
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_0, 0)
        )
        sm_snapshot.match("create_secret_rs_0", create_secret_rs_0)

        put_secret_value_res_0 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString="S1", VersionStages=["one", "two", "three"]
        )
        sm_snapshot.match("put_secret_value_res_0", put_secret_value_res_0)

        list_secret_version_ids_res_0 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_0", list_secret_version_ids_res_0)

        put_secret_value_res_1 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name,
            SecretString="S2",
            VersionStages=["one", "two", "three", "four"],
        )
        sm_snapshot.match("put_secret_value_res_1", put_secret_value_res_1)

        list_secret_version_ids_res_1 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_1", list_secret_version_ids_res_1)

        delete_secret_res_0 = aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )
        sm_snapshot.match("delete_secret_res_0", delete_secret_res_0)

    @markers.snapshot.skip_snapshot_verify(paths=["$..KmsKeyId", "$..KmsKeyIds"])
    @markers.aws.unknown
    def test_non_versioning_version_stages_no_replacement(
        self, sm_snapshot, secret_name, aws_client
    ):
        create_secret_rs_0 = aws_client.secretsmanager.create_secret(
            Name=secret_name, SecretString="S0"
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_0, 0)
        )
        sm_snapshot.match("create_secret_rs_0", create_secret_rs_0)

        put_secret_value_res_0 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString="S1", VersionStages=["one", "two", "three"]
        )
        sm_snapshot.match("put_secret_value_res_0", put_secret_value_res_0)

        list_secret_version_ids_res_0 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_0", list_secret_version_ids_res_0)

        put_secret_value_res_1 = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString="S2", VersionStages=["one", "two", "four"]
        )
        sm_snapshot.match("put_secret_value_res_1", put_secret_value_res_1)

        list_secret_version_ids_res_1 = aws_client.secretsmanager.list_secret_version_ids(
            SecretId=secret_name
        )
        sm_snapshot.match("list_secret_version_ids_res_1", list_secret_version_ids_res_1)

        delete_secret_res_0 = aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )
        sm_snapshot.match("delete_secret_res_0", delete_secret_res_0)

    @staticmethod
    def secretsmanager_http_json_headers(amz_target: str) -> dict:
        headers = mock_aws_request_headers(
            "secretsmanager",
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            region_name=TEST_AWS_REGION_NAME,
        )
        headers["X-Amz-Target"] = amz_target
        return headers

    def secretsmanager_http_json_post(self, amz_target: str, http_body: json) -> requests.Response:
        ep_url: str = aws_stack.get_local_service_url("secretsmanager")
        http_headers: dict = self.secretsmanager_http_json_headers(amz_target)
        return requests.post(ep_url, headers=http_headers, data=json.dumps(http_body))

    def secretsmanager_http_create_secret_string(
        self, secret_name: str, secret_string: str
    ) -> requests.Response:
        http_body: json = {"Name": secret_name, "SecretString": secret_string}
        return self.secretsmanager_http_json_post("secretsmanager.CreateSecret", http_body)

    @staticmethod
    def secretsmanager_http_create_secret_string_val_res(
        res: requests.Response, secret_name: str
    ) -> json:
        assert res.status_code == 200
        res_json: json = res.json()
        assert res_json["Name"] == secret_name
        return res_json

    def secretsmanager_http_delete_secret(self, secret_id: str) -> requests.Response:
        http_body: json = {"SecretId": secret_id}
        return self.secretsmanager_http_json_post("secretsmanager.DeleteSecret", http_body)

    @staticmethod
    def secretsmanager_http_delete_secret_val_res(res: requests.Response, secret_id: str) -> json:
        assert res.status_code == 200
        res_json: json = res.json()
        assert res_json["Name"] == secret_id
        return res_json

    def secretsmanager_http_get_secret_value(self, secret_id: str) -> requests.Response:
        http_body: json = {"SecretId": secret_id}
        return self.secretsmanager_http_json_post("secretsmanager.GetSecretValue", http_body)

    @staticmethod
    def secretsmanager_http_get_secret_value_val_res(
        res: requests.Response, secret_name: str, secret_string: str, version_id: str
    ) -> json:
        assert res.status_code == 200
        res_json: json = res.json()
        assert res_json["Name"] == secret_name
        assert res_json["SecretString"] == secret_string
        assert res_json["VersionId"] == version_id
        return res_json

    def secretsmanager_http_get_secret_value_with(
        self, secret_id: str, version_stage: str
    ) -> requests.Response:
        http_body: json = {"SecretId": secret_id, "VersionStage": version_stage}
        return self.secretsmanager_http_json_post("secretsmanager.GetSecretValue", http_body)

    @staticmethod
    def secretsmanager_http_get_secret_value_with_val_res(
        res: requests.Response,
        secret_name: str,
        secret_string: str,
        version_id: str,
        version_stage: str,
    ) -> json:
        res_json = TestSecretsManager.secretsmanager_http_get_secret_value_val_res(
            res, secret_name, secret_string, version_id
        )
        assert res_json["VersionStages"] == [version_stage]
        return res_json

    def secretsmanager_http_list_secret_version_ids(self, secret_id: str) -> requests.Response:
        http_body: json = {"SecretId": secret_id}
        return self.secretsmanager_http_json_post("secretsmanager.ListSecretVersionIds", http_body)

    @staticmethod
    def secretsmanager_http_list_secret_version_ids_val_res(
        res: requests.Response, secret_name: str, versions: json
    ) -> json:
        assert res.status_code == 200
        res_json: json = res.json()
        assert res_json["Name"] == secret_name
        res_versions: [json] = res_json["Versions"]
        assert len(res_versions) == len(versions)
        assert len(set([rv["VersionId"] for rv in res_versions])) == len(res_versions)
        assert len(set([v["VersionId"] for v in versions])) == len(versions)
        for version in versions:
            vs_in_res: [json] = list(
                filter(lambda rv: rv["VersionId"] == version["VersionId"], res_versions)
            )
            assert len(vs_in_res) == 1
            v_in_res = vs_in_res[0]
            assert v_in_res["VersionStages"] == version["VersionStages"]
        return res_json

    def secretsmanager_http_put_secret_value(
        self, secret_id: str, secret_string: str
    ) -> requests.Response:
        http_body: json = {
            "SecretId": secret_id,
            "SecretString": secret_string,
        }
        return self.secretsmanager_http_json_post("secretsmanager.PutSecretValue", http_body)

    @staticmethod
    def secretsmanager_http_put_secret_value_val_res(
        res: requests.Response, secret_name: str
    ) -> json:
        assert res.status_code == 200
        res_json: json = res.json()
        assert res_json["Name"] == secret_name
        return res_json

    def secretsmanager_http_put_pending_secret_value(
        self, secret_id: str, secret_string: str
    ) -> requests.Response:
        http_body: json = {
            "SecretId": secret_id,
            "SecretString": secret_string,
            "VersionStages": ["AWSPENDING"],
        }
        return self.secretsmanager_http_json_post("secretsmanager.PutSecretValue", http_body)

    @staticmethod
    def secretsmanager_http_put_pending_secret_value_val_res(
        res: requests.Response, secret_name: str
    ) -> json:
        return TestSecretsManager.secretsmanager_http_put_secret_value_val_res(res, secret_name)

    def secretsmanager_http_put_secret_value_with(
        self, secret_id: str, secret_string: str, client_request_token: Optional[str]
    ) -> requests.Response:
        http_body: json = {
            "SecretId": secret_id,
            "SecretString": secret_string,
            "ClientRequestToken": client_request_token,
        }
        return self.secretsmanager_http_json_post("secretsmanager.PutSecretValue", http_body)

    @staticmethod
    def secretsmanager_http_put_secret_value_with_val_res(
        res: requests.Response, secret_name: str, client_request_token: str
    ) -> json:
        assert res.status_code == 200
        res_json: json = res.json()
        assert res_json["Name"] == secret_name
        assert res_json["VersionId"] == client_request_token
        return res_json

    def secretsmanager_http_update_secret(
        self, secret_id: str, secret_string: str, client_request_token: Optional[str]
    ):
        http_body: json = {"SecretId": secret_id, "SecretString": secret_string}
        if client_request_token:
            http_body["ClientRequestToken"] = client_request_token
        return self.secretsmanager_http_json_post("secretsmanager.UpdateSecret", http_body)

    @staticmethod
    def secretsmanager_http_update_secret_val_res(
        res: requests.Response, secret_name: str, client_request_token: Optional[str]
    ):
        assert res.status_code == 200
        res_json: json = res.json()
        assert res_json["Name"] == secret_name
        if client_request_token:
            assert res_json["VersionId"] == client_request_token
        return res_json

    def secretsmanager_http_put_secret_value_with_version(
        self,
        secret_id: str,
        secret_string: str,
        client_request_token: Optional[str],
        version_stages: list[str],
    ) -> requests.Response:
        http_body: json = {
            "SecretId": secret_id,
            "SecretString": secret_string,
            "ClientRequestToken": client_request_token,
            "VersionStages": version_stages,
        }
        return self.secretsmanager_http_json_post("secretsmanager.PutSecretValue", http_body)

    @staticmethod
    def secretsmanager_http_put_secret_value_with_version_val_res(
        res: requests.Response,
        secret_name: str,
        client_request_token: Optional[str],
        version_stages: list[str],
    ) -> json:
        req_version_id: str
        if client_request_token is None:
            assert res.status_code == 200
            req_version_id = res.json()["VersionId"]
        else:
            req_version_id = client_request_token
        res_json = TestSecretsManager.secretsmanager_http_put_secret_value_with_val_res(
            res, secret_name, req_version_id
        )
        assert res_json["VersionStages"] == version_stages
        return res_json

    @markers.aws.unknown
    def test_update_secret_with_non_provided_client_request_token(self, aws_client, secret_name):
        # Create v0.
        secret_string_v0: str = "secret_string_v0"
        cr_v0_res_json: json = aws_client.secretsmanager.create_secret(
            Name=secret_name,
            SecretString=secret_string_v0,
        )
        version_id_v0 = cr_v0_res_json["VersionId"]

        # Update with client request token.
        secret_string_v1: str = "secret_string_v1"
        version_id_v1: str = str(uuid.uuid4())
        self.secretsmanager_http_update_secret_val_res(
            self.secretsmanager_http_update_secret(secret_name, secret_string_v1, version_id_v1),
            secret_name,
            version_id_v1,
        )

        # Get.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v1,
            version_id_v1,
        )

        # Update without client request token, the SDK will generate it.
        secret_string_v2: str = "secret_string_v2"
        res_update_json = aws_client.secretsmanager.update_secret(
            SecretId=secret_name,
            SecretString=secret_string_v2,
        )

        version_id_v2 = res_update_json["VersionId"]
        assert version_id_v2 != version_id_v1
        assert version_id_v2 != version_id_v0

        # Get.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v2,
            version_id_v2,
        )

    @markers.aws.unknown
    def test_put_secret_value_with_new_custom_client_request_token(self, secret_name, aws_client):
        # Create v0.
        secret_string_v0: str = "MySecretString"
        cr_v0_res_json: json = aws_client.secretsmanager.create_secret(
            Name=secret_name,
            SecretString=secret_string_v0,
        )
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json["VersionId"],
        )

        # Update v0 with predefined ClientRequestToken.
        secret_string_v1: str = "MyNewSecretString"
        #
        crt_v1: str = str(uuid.uuid4())
        while crt_v1 == cr_v0_res_json["VersionId"]:
            crt_v1 = str(uuid.uuid4())
        #
        self.secretsmanager_http_put_secret_value_val_res(
            self.secretsmanager_http_put_secret_value_with(secret_name, secret_string_v1, crt_v1),
            secret_name,
        )
        #
        # Check v1 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v1,
            crt_v1,
        )
        #
        # Check versioning base consistency.
        versions_v0_v1: json = [
            {"VersionId": cr_v0_res_json["VersionId"], "VersionStages": ["AWSPREVIOUS"]},
            {"VersionId": crt_v1, "VersionStages": ["AWSCURRENT"]},
        ]
        self.secretsmanager_http_list_secret_version_ids_val_res(
            self.secretsmanager_http_list_secret_version_ids(secret_name),
            secret_name,
            versions_v0_v1,
        )

        self.secretsmanager_http_delete_secret_val_res(
            self.secretsmanager_http_delete_secret(secret_name), secret_name
        )

    @markers.aws.unknown
    def test_http_put_secret_value_with_duplicate_client_request_token(
        self, secret_name, aws_client
    ):
        # Create v0.
        secret_string_v0: str = "MySecretString"
        cr_v0_res_json: json = aws_client.secretsmanager.create_secret(
            Name=secret_name,
            SecretString=secret_string_v0,
        )

        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json["VersionId"],
        )

        # Update v0 with duplicate ClientRequestToken.
        secret_string_v1: str = "MyNewSecretString"
        #
        crt_v1: str = cr_v0_res_json["VersionId"]
        #
        self.secretsmanager_http_put_secret_value_val_res(
            self.secretsmanager_http_put_secret_value_with(secret_name, secret_string_v1, crt_v1),
            secret_name,
        )
        #
        # Check v1 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v1,
            crt_v1,
        )
        #
        # Check versioning base consistency.
        versions_v0_v1: json = [{"VersionId": crt_v1, "VersionStages": ["AWSCURRENT"]}]
        self.secretsmanager_http_list_secret_version_ids_val_res(
            self.secretsmanager_http_list_secret_version_ids(secret_name),
            secret_name,
            versions_v0_v1,
        )

        self.secretsmanager_http_delete_secret_val_res(
            self.secretsmanager_http_delete_secret(secret_name), secret_name
        )

    @markers.aws.unknown
    def test_http_put_secret_value_with_non_provided_client_request_token(
        self, secret_name, aws_client
    ):
        # Create v0.
        secret_string_v0: str = "MySecretString"
        cr_v0_res_json: json = aws_client.secretsmanager.create_secret(
            Name=secret_name,
            SecretString=secret_string_v0,
        )

        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json["VersionId"],
        )

        # Update v0 with non-provided ClientRequestToken (the SDK will generate one).
        secret_string_v1: str = "MyNewSecretString"
        pv_v1_res_json = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString=secret_string_v1
        )
        # Check v1 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v1,
            pv_v1_res_json["VersionId"],
        )

        # Check versioning base consistency.
        versions_v0_v1: json = [
            {"VersionId": cr_v0_res_json["VersionId"], "VersionStages": ["AWSPREVIOUS"]},
            {"VersionId": pv_v1_res_json["VersionId"], "VersionStages": ["AWSCURRENT"]},
        ]
        self.secretsmanager_http_list_secret_version_ids_val_res(
            self.secretsmanager_http_list_secret_version_ids(secret_name),
            secret_name,
            versions_v0_v1,
        )

        self.secretsmanager_http_delete_secret_val_res(
            self.secretsmanager_http_delete_secret(secret_name), secret_name
        )

    @markers.aws.unknown
    def test_http_put_secret_value_duplicate_req(self, secret_name, aws_client):
        # Create v0.
        secret_string_v0: str = "MySecretString"
        cr_v0_res_json: json = aws_client.secretsmanager.create_secret(
            Name=secret_name,
            SecretString=secret_string_v0,
        )
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json["VersionId"],
        )

        # Duplicate update.
        self.secretsmanager_http_put_secret_value_val_res(
            self.secretsmanager_http_put_secret_value_with(
                secret_name, secret_string_v0, cr_v0_res_json["VersionId"]
            ),
            secret_name,
        )
        #
        # Check v1 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json["VersionId"],
        )
        #
        # Check versioning base consistency.
        versions_v0_v1: json = [
            {"VersionId": cr_v0_res_json["VersionId"], "VersionStages": ["AWSCURRENT"]},
        ]
        self.secretsmanager_http_list_secret_version_ids_val_res(
            self.secretsmanager_http_list_secret_version_ids(secret_name),
            secret_name,
            versions_v0_v1,
        )

        self.secretsmanager_http_delete_secret_val_res(
            self.secretsmanager_http_delete_secret(secret_name), secret_name
        )

    @markers.aws.unknown
    def test_http_put_secret_value_null_client_request_token_new_version_stages(
        self, secret_name, aws_client
    ):
        # Create v0.
        secret_string_v0: str = "MySecretString"
        cr_v0_res_json: json = aws_client.secretsmanager.create_secret(
            Name=secret_name,
            SecretString=secret_string_v0,
        )
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json["VersionId"],
        )

        # Update v0 with null ClientRequestToken (auto-generated by SDK).
        secret_string_v1: str = "MyNewSecretString"
        version_stages_v1: list[str] = ["AWSPENDING"]

        pv_v1_res_json = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_name,
            SecretString=secret_string_v1,
            VersionStages=version_stages_v1,
        )

        assert pv_v1_res_json["VersionId"] != cr_v0_res_json["VersionId"]

        # Check v1 base consistency.
        self.secretsmanager_http_get_secret_value_with_val_res(
            self.secretsmanager_http_get_secret_value_with(secret_name, "AWSPENDING"),
            secret_name,
            secret_string_v1,
            pv_v1_res_json["VersionId"],
            "AWSPENDING",
        )

        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json["VersionId"],
        )

        # Check versioning base consistency.
        versions_v0_v1: json = [
            {"VersionId": cr_v0_res_json["VersionId"], "VersionStages": ["AWSCURRENT"]},
            {"VersionId": pv_v1_res_json["VersionId"], "VersionStages": ["AWSPENDING"]},
        ]
        self.secretsmanager_http_list_secret_version_ids_val_res(
            self.secretsmanager_http_list_secret_version_ids(secret_name),
            secret_name,
            versions_v0_v1,
        )

        self.secretsmanager_http_delete_secret_val_res(
            self.secretsmanager_http_delete_secret(secret_name), secret_name
        )

    @markers.aws.unknown
    def test_http_put_secret_value_custom_client_request_token_new_version_stages(
        self,
        secret_name,
        aws_client,
    ):
        # Create v0.
        secret_string_v0: str = "MySecretString"
        cr_v0_res_json: json = aws_client.secretsmanager.create_secret(
            Name=secret_name,
            SecretString=secret_string_v0,
        )

        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json["VersionId"],
        )

        # Update v0 with new ClientRequestToken.
        secret_string_v1: str = "MyNewSecretString"
        version_stages_v1: list[str] = ["AWSPENDING"]
        crt_v1: str = str(uuid.uuid4())
        while crt_v1 == cr_v0_res_json["VersionId"]:
            crt_v1 = str(uuid.uuid4())

        self.secretsmanager_http_put_secret_value_with_version_val_res(
            self.secretsmanager_http_put_secret_value_with_version(
                secret_name, secret_string_v1, crt_v1, version_stages_v1
            ),
            secret_name,
            crt_v1,
            version_stages_v1,
        )

        # Check v1 base consistency.
        self.secretsmanager_http_get_secret_value_with_val_res(
            self.secretsmanager_http_get_secret_value_with(secret_name, "AWSPENDING"),
            secret_name,
            secret_string_v1,
            crt_v1,
            "AWSPENDING",
        )

        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json["VersionId"],
        )

        # Check versioning base consistency.
        versions_v0_v1: json = [
            {"VersionId": cr_v0_res_json["VersionId"], "VersionStages": ["AWSCURRENT"]},
            {"VersionId": crt_v1, "VersionStages": ["AWSPENDING"]},
        ]
        self.secretsmanager_http_list_secret_version_ids_val_res(
            self.secretsmanager_http_list_secret_version_ids(secret_name),
            secret_name,
            versions_v0_v1,
        )

        self.secretsmanager_http_delete_secret_val_res(
            self.secretsmanager_http_delete_secret(secret_name), secret_name
        )

    @markers.aws.unknown
    def test_delete_non_existent_secret_returns_as_if_secret_exists(self, secret_name, aws_client):
        """When ForceDeleteWithoutRecovery=True, AWS responds as if the non-existent secret was successfully deleted."""
        response = aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )

        assert response["Name"] == secret_name
        assert response["ARN"] is not None
        assert response["DeletionDate"] is not None

    @markers.aws.unknown
    def test_exp_raised_on_creation_of_secret_scheduled_for_deletion(
        self, sm_snapshot, secret_name, aws_client
    ):
        create_secret_req: CreateSecretRequest = CreateSecretRequest(
            Name=secret_name, SecretString=f"secretstr-{short_uid()}"
        )
        stage_deletion_req: DeleteSecretRequest = DeleteSecretRequest(
            SecretId=create_secret_req["Name"], RecoveryWindowInDays=7
        )

        res = aws_client.secretsmanager.create_secret(**create_secret_req)
        create_secret_res: CreateSecretResponse = select_from_typed_dict(CreateSecretResponse, res)
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_res, 0)
        )

        res = aws_client.secretsmanager.delete_secret(**stage_deletion_req)
        delete_res: DeleteSecretResponse = select_from_typed_dict(DeleteSecretResponse, res)
        sm_snapshot.match("delete_res", delete_res)

        with pytest.raises(Exception) as invalid_req_ex:
            aws_client.secretsmanager.create_secret(**create_secret_req)
        sm_snapshot.match("invalid_req_ex", invalid_req_ex.value.response)

    @markers.aws.unknown
    def test_can_recreate_delete_secret(self, sm_snapshot, secret_name, aws_client):
        # NOTE: AWS will behave as staged deletion for a small number of seconds (<10).
        # We assume forced deletion is instantaneous, until the precise behaviour is understood.

        create_secret_req: CreateSecretRequest = CreateSecretRequest(
            Name=secret_name, SecretString=f"secretstr-{short_uid()}"
        )
        stage_deletion_req: DeleteSecretRequest = DeleteSecretRequest(
            SecretId=create_secret_req["Name"], ForceDeleteWithoutRecovery=True
        )

        res = aws_client.secretsmanager.create_secret(**create_secret_req)
        create_secret_res_0: CreateSecretResponse = select_from_typed_dict(
            CreateSecretResponse, res
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_res_0, 0)
        )
        sm_snapshot.match("create_secret_res_0", create_secret_res_0)

        res = aws_client.secretsmanager.delete_secret(**stage_deletion_req)
        delete_res_1: DeleteSecretResponse = select_from_typed_dict(DeleteSecretResponse, res)
        sm_snapshot.match("delete_res_1", delete_res_1)

        self._wait_force_deletion_completed(
            aws_client.secretsmanager, stage_deletion_req["SecretId"]
        )

        res = aws_client.secretsmanager.create_secret(**create_secret_req)
        create_secret_res_1: CreateSecretResponse = select_from_typed_dict(
            CreateSecretResponse, res
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_res_1, 1)
        )
        sm_snapshot.match("create_secret_res_1", create_secret_res_1)

        aws_client.secretsmanager.delete_secret(**stage_deletion_req)

    @markers.aws.validated
    def test_secret_exists(self, cleanups, aws_client):
        secret_name = short_uid()
        cleanups.append(
            lambda: aws_client.secretsmanager.delete_secret(
                SecretId=secret_name, ForceDeleteWithoutRecovery=True
            )
        )
        description = "Testing secret already exists."
        rs = aws_client.secretsmanager.create_secret(
            Name=secret_name,
            SecretString="my_secret_{}".format(secret_name),
            Description=description,
        )
        self._wait_created_is_listed(aws_client.secretsmanager, secret_id=secret_name)
        secret_arn = rs["ARN"]
        secret_id = rs["Name"]
        assert len(secret_arn.rpartition("-")[-1]) == 6

        ls = aws_client.secretsmanager.list_secrets()
        secrets = {
            secret["Name"]: secret["ARN"]
            for secret in ls["SecretList"]
            if secret["Name"] == secret_name
        }
        assert len(secrets.keys()) == 1
        assert secret_arn in secrets.values()

        with pytest.raises(
            aws_client.secretsmanager.exceptions.ResourceExistsException
        ) as res_exists_ex:
            aws_client.secretsmanager.create_secret(
                Name=secret_name,
                SecretString="my_secret_{}".format(secret_name),
                Description=description,
            )
        assert res_exists_ex.typename == "ResourceExistsException"
        assert res_exists_ex.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
        assert (
            res_exists_ex.value.response["Error"]["Message"]
            == f"The operation failed because the secret {secret_id} already exists."
        )

        # clean up
        aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )

    @markers.aws.validated
    def test_secret_exists_snapshots(self, sm_snapshot, cleanups, aws_client):
        secret_name = short_uid()
        cleanups.append(
            lambda: aws_client.secretsmanager.delete_secret(
                SecretId=secret_name, ForceDeleteWithoutRecovery=True
            )
        )

        description = "Snapshot testing secret already exists."
        rs = aws_client.secretsmanager.create_secret(
            Name=secret_name,
            SecretString="my_secret_{}".format(secret_name),
            Description=description,
        )
        self._wait_created_is_listed(aws_client.secretsmanager, secret_id=secret_name)
        sm_snapshot.add_transformers_list(sm_snapshot.transform.secretsmanager_secret_id_arn(rs, 0))

        with pytest.raises(
            aws_client.secretsmanager.exceptions.ResourceExistsException
        ) as res_exists_ex:
            aws_client.secretsmanager.create_secret(
                Name=secret_name,
                SecretString="my_secret_{}".format(secret_name),
                Description=description,
            )
        sm_snapshot.match("ex_log", res_exists_ex.value.response)

        # clean up
        delete_secret_res = aws_client.secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )
        sm_snapshot.match("delete_secret_res", delete_secret_res)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "operation",
        [
            "CreateSecret",
            "UpdateSecret",
            "RotateSecret",
            "PutSecretValue",
        ],
    )
    def test_no_client_request_token(
        self, aws_client, sm_snapshot, cleanups, aws_http_client_factory, operation
    ):
        # https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/create-secret.html#options
        secret_name = short_uid()
        # we should need to clean up but better safe than sorry
        cleanups.append(
            lambda: aws_client.secretsmanager.delete_secret(
                SecretId=secret_name, ForceDeleteWithoutRecovery=True
            )
        )

        client = aws_http_client_factory("secretsmanager", signer_factory=SigV4Auth)
        # When using the SDK or CLI, it will automatically create and add ClientRequestToken to your request
        # try to not append it to see what exception AWS returns
        parameters = {"SecretString": "thisisthesecret", "Description": "My secret string"}
        if operation == "CreateSecret":
            parameters["Name"] = secret_name
        else:
            parameters["SecretId"] = secret_name

        headers = {
            "X-Amz-Target": f"secretsmanager.{operation}",
            "Content-Type": "application/x-amz-json-1.1",
        }

        response = client.post("/", data=json.dumps(parameters), headers=headers)
        exc_response = {"Error": response.json(), "Metadata": {"StatusCode": response.status_code}}

        sm_snapshot.match("no-client-request-exc", exc_response)

    @markers.aws.validated
    def test_create_secret_version_from_empty_secret(self, aws_client, snapshot, cleanups):
        snapshot.add_transformer(snapshot.transform.resource_name("secret-version"), priority=-1)
        snapshot.add_transformer(snapshot.transform.key_value("Name"))

        response = aws_client.secretsmanager.create_secret(
            Name=f"test-version-{short_uid()}", Description=""
        )
        snapshot.match("create-empty-secret", response)
        secret_id = response["ARN"]
        cleanups.append(
            lambda: aws_client.secretsmanager.delete_secret(
                SecretId=secret_id, ForceDeleteWithoutRecovery=True
            )
        )

        response = aws_client.secretsmanager.describe_secret(SecretId=secret_id)
        snapshot.match("describe-secret", response)

        response = aws_client.secretsmanager.put_secret_value(
            SecretId=secret_id, SecretString="example-string-to-protect"
        )
        snapshot.match("put-secret-value", response)
