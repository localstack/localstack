import json
import logging
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Set

import pytest
import requests
from py._code.code import ExceptionInfo

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api.secretsmanager import (
    CreateSecretRequest,
    CreateSecretResponse,
    DeleteResourcePolicyResponse,
    DeleteSecretRequest,
    DeleteSecretResponse,
    DescribeSecretResponse,
    GetResourcePolicyResponse,
    GetSecretValueResponse,
    ListSecretsResponse,
    PutResourcePolicyResponse,
    PutSecretValueResponse,
    UpdateSecretResponse,
)
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON36
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.collections import select_from_typed_dict
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition
from localstack.utils.time import today_no_time
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_PYTHON_VERSION
from tests.integration.secretsmanager.functions import lambda_rotate_secret

LOG = logging.getLogger(__name__)


RESOURCE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::%s:root" % get_aws_account_id()},
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "*",
        }
    ],
}

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_ROTATE_SECRET = os.path.join(THIS_FOLDER, "functions", "lambda_rotate_secret.py")


class TestSecretsManager:
    @pytest.fixture
    def sm_client(self, secretsmanager_client):
        return secretsmanager_client

    @pytest.fixture()
    def sm_snapshot(self, snapshot):
        snapshot.add_transformers_list(snapshot.transform.secretsmanager_api())
        return snapshot

    @staticmethod
    def _snapshot_obj_of_exception(ex: ExceptionInfo) -> Dict:
        return {"typename": ex.typename, "message": str(ex.value)}

    @staticmethod
    def _typed_response_of(typ: type, response: Dict) -> Dict:
        return select_from_typed_dict(typ, response)

    @staticmethod
    def _wait_created_is_listed(client, secret_id: str):
        def _is_secret_in_list():
            lst: ListSecretsResponse = TestSecretsManager._typed_response_of(
                typ=ListSecretsResponse, response=client.list_secrets()
            )
            secret_ids: Set[str] = {secret["Name"] for secret in lst.get("SecretList", [])}
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

    @pytest.mark.parametrize(
        "secret_name, is_valid_partial_arn",
        [
            ("s-c64bdc03", True),
            ("Valid/_+=.@-Name", True),
            ("Valid/_+=.@-Name-a1b2", True),
            ("Valid/_+=.@-Name-a1b2c3-", True),
            ("Invalid/_+=.@-Name-a1b2c3", False),
        ],
    )
    def test_create_and_update_secret(
        self, sm_client, secret_name: str, is_valid_partial_arn: bool, sm_snapshot
    ):
        description = "Testing secret creation."
        create_secret_rs_1: CreateSecretResponse = self._typed_response_of(
            typ=CreateSecretResponse,
            response=sm_client.create_secret(
                Name=secret_name,
                SecretString="my_secret",
                Description=description,
            ),
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_1, 0)
        )
        sm_snapshot.match("create_secret_rs_1", create_secret_rs_1)
        #
        secret_arn = create_secret_rs_1["ARN"]
        assert len(secret_arn.rpartition("-")[-1]) == 6

        get_secret_value_rs_1: GetSecretValueResponse = self._typed_response_of(
            typ=GetSecretValueResponse, response=sm_client.get_secret_value(SecretId=secret_name)
        )
        sm_snapshot.match("get_secret_value_rs_1", get_secret_value_rs_1)

        describe_secret_rs_1: DescribeSecretResponse = self._typed_response_of(
            typ=DescribeSecretResponse, response=sm_client.describe_secret(SecretId=secret_name)
        )
        sm_snapshot.match("describe_secret_rs_1", describe_secret_rs_1)

        get_secret_value_rs_2: GetSecretValueResponse = self._typed_response_of(
            typ=GetSecretValueResponse, response=sm_client.get_secret_value(SecretId=secret_arn)
        )
        sm_snapshot.match("get_secret_value_rs_2", get_secret_value_rs_2)

        if is_valid_partial_arn:
            get_secret_value_rs_3: GetSecretValueResponse = self._typed_response_of(
                typ=GetSecretValueResponse,
                response=sm_client.get_secret_value(SecretId=secret_arn[:-7]),
            )
            sm_snapshot.match("get_secret_value_rs_3", get_secret_value_rs_3)
        else:
            with pytest.raises(Exception) as resource_not_found:
                sm_client.get_secret_value(SecretId=secret_arn[:-7])
            resource_not_found_dict_1 = self._snapshot_obj_of_exception(resource_not_found)
            sm_snapshot.match("resource_not_found_dict_1", resource_not_found_dict_1)

        put_secret_value_rs_1: GetSecretValueResponse = self._typed_response_of(
            typ=PutSecretValueResponse,
            response=sm_client.put_secret_value(SecretId=secret_name, SecretString="new_secret"),
        )
        sm_snapshot.match("put_secret_value_rs_1", put_secret_value_rs_1)

        get_secret_value_rs_4: GetSecretValueResponse = self._typed_response_of(
            typ=GetSecretValueResponse, response=sm_client.get_secret_value(SecretId=secret_name)
        )
        sm_snapshot.match("get_secret_value_rs_4", get_secret_value_rs_4)

        # update secret by ARN
        update_secret_res_1: UpdateSecretResponse = self._typed_response_of(
            typ=UpdateSecretResponse,
            response=sm_client.update_secret(
                SecretId=secret_arn, SecretString="test123", Description="d1"
            ),
        )
        sm_snapshot.match("update_secret_res_1", update_secret_res_1)

        # clean up
        delete_secret_res_1: DeleteSecretResponse = self._typed_response_of(
            typ=DeleteSecretResponse,
            response=sm_client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True),
        )
        sm_snapshot.match("delete_secret_res_1", delete_secret_res_1)

    def test_call_lists_secrets_multiple_times(self, sm_client, sm_snapshot):
        secret_name = f"s-{short_uid()}"
        create_secret_rs_1: CreateSecretResponse = self._typed_response_of(
            typ=CreateSecretResponse,
            response=sm_client.create_secret(
                Name=secret_name,
                SecretString="my_secret",
                Description="testing creation of secrets",
            ),
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_1, 0)
        )
        sm_snapshot.match("create_secret_rs_1", create_secret_rs_1)

        self._wait_created_is_listed(sm_client, secret_id=secret_name)

        # call list_secrets multiple times
        for i in range(3):
            list_secrets_res = self._typed_response_of(
                typ=ListSecretsResponse, response=sm_client.list_secrets()
            )
            sm_snapshot.match(f"list_secrets_res_{i}", list_secrets_res)

        # clean up
        delete_secret_res_1: DeleteSecretResponse = self._typed_response_of(
            typ=DeleteSecretResponse,
            response=sm_client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True),
        )
        sm_snapshot.match("delete_secret_res_1", delete_secret_res_1)

    def test_create_multi_secrets(self, sm_client, sm_snapshot):
        secret_names = [short_uid() for _ in range(3)]
        for i, secret_name in enumerate(secret_names):
            create_secret_rs_1: CreateSecretResponse = self._typed_response_of(
                typ=CreateSecretResponse,
                response=sm_client.create_secret(
                    Name=secret_name,
                    SecretString=f"my_secret_{secret_name}",
                    Description="Testing secrets creation.",
                ),
            )
            sm_snapshot.add_transformers_list(
                sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_1, i)
            )

            self._wait_created_is_listed(sm_client, secret_name)

        list_secrets_res = self._typed_response_of(
            typ=ListSecretsResponse, response=sm_client.list_secrets()
        )
        sm_snapshot.match(f"list_secrets_res", list_secrets_res)

        # clean up
        for i, secret_name in enumerate(secret_names):
            delete_secret_res: DeleteSecretResponse = self._typed_response_of(
                typ=DeleteSecretResponse,
                response=sm_client.delete_secret(
                    SecretId=secret_name, ForceDeleteWithoutRecovery=True
                ),
            )
            sm_snapshot.match(f"delete_secret_res{i}", delete_secret_res)

    def test_get_random_exclude_characters_and_symbols(self, sm_client):
        random_password = sm_client.get_random_password(
            PasswordLength=120, ExcludeCharacters="xyzDje@?!."
        )

        assert len(random_password["RandomPassword"]) == 120
        assert all(c not in "xyzDje@?!." for c in random_password["RandomPassword"])

    def test_resource_policy(self, sm_client):
        secret_name = f"s-{short_uid()}"

        sm_client.create_secret(
            Name=secret_name,
            SecretString="my_secret",
            Description="testing creation of secrets",
        )

        sm_client.put_resource_policy(
            SecretId=secret_name, ResourcePolicy=json.dumps(RESOURCE_POLICY)
        )

        rs = sm_client.get_resource_policy(SecretId=secret_name)

        policy = json.loads(rs["ResourcePolicy"])

        assert policy["Version"] == RESOURCE_POLICY["Version"]
        assert policy["Statement"] == RESOURCE_POLICY["Statement"]

        rs = sm_client.delete_resource_policy(SecretId=secret_name)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        # clean up
        sm_client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)

    def test_rotate_secret_with_lambda_1(self, sm_client):
        secret_name = f"s-{short_uid()}"

        sm_client.create_secret(
            Name=secret_name,
            SecretString="my_secret",
            Description="testing rotation of secrets",
        )

        function_name = "s-%s" % short_uid()
        function_arn = testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_VERSION,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )["CreateFunctionResponse"]["FunctionArn"]

        response = sm_client.rotate_secret(
            SecretId=secret_name,
            RotationLambdaARN=function_arn,
            RotationRules={
                "AutomaticallyAfterDays": 1,
            },
            RotateImmediately=True,
        )

        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # clean up
        sm_client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
        testutil.delete_lambda_function(function_name)

    def test_rotate_secret_with_lambda_2(self, sm_client):
        secret_name = f"s-{short_uid()}"

        cre_res = sm_client.create_secret(
            Name=secret_name,
            SecretString="init",
            Description="testing rotation of secrets",
        )
        version_id_0 = cre_res["VersionId"]

        function_name = f"rotate-func-{short_uid()}"
        function_arn = testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_ROTATE_SECRET,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )["CreateFunctionResponse"]["FunctionArn"]

        rot_res = sm_client.rotate_secret(
            SecretId=secret_name,
            RotationLambdaARN=function_arn,
            RotationRules={
                "AutomaticallyAfterDays": 1,
            },
            RotateImmediately=True,
        )
        version_id_1 = rot_res["VersionId"]
        assert version_id_0 != version_id_1

        # Assert secretsmanager promoted the creation of the new secret version by reporting resource not found
        # exception on pending secret version.
        sig_rnfe_1 = lambda_rotate_secret.secret_signal_resource_not_found_exception_on_create(
            version_id_1
        )
        get_sig_rnfe_1 = sm_client.get_secret_value(SecretId=sig_rnfe_1)
        assert get_sig_rnfe_1["Name"] == sig_rnfe_1
        assert get_sig_rnfe_1["SecretString"] == sig_rnfe_1

        des = sm_client.describe_secret(SecretId=secret_name)
        assert des["RotationEnabled"]
        assert des["RotationRules"] == {"AutomaticallyAfterDays": 1}
        assert des["RotationLambdaARN"] == function_arn

        lst_res = sm_client.list_secret_version_ids(SecretId=secret_name)
        versions = lst_res["Versions"]
        assert len(versions) == 2

        get_res_v0 = sm_client.get_secret_value(SecretId=secret_name, VersionId=version_id_0)
        assert get_res_v0["VersionId"] == version_id_0
        assert get_res_v0["SecretString"] == "init"

        get_res_v1 = sm_client.get_secret_value(SecretId=secret_name, VersionId=version_id_1)
        assert get_res_v1["VersionId"] == version_id_1
        secret_string_1 = lambda_rotate_secret.secret_of_rotation_from_version_id(version_id_1)
        assert get_res_v1["SecretString"] == secret_string_1

        get_res = sm_client.get_secret_value(SecretId=secret_name)
        assert get_res["VersionId"] == version_id_1
        assert get_res["SecretString"] == secret_string_1

        rot_2_res = sm_client.rotate_secret(
            SecretId=secret_name,
            RotationLambdaARN=function_arn,
            RotationRules={
                "AutomaticallyAfterDays": 1,
            },
            RotateImmediately=True,
        )
        version_id_2 = rot_2_res["VersionId"]
        assert len({version_id_0, version_id_1, version_id_2}) == 3

        # Assert secretsmanager promoted the creation of the new secret version by reporting resource not found
        # exception on pending secret version.
        sig_rnfe_2 = lambda_rotate_secret.secret_signal_resource_not_found_exception_on_create(
            version_id_2
        )
        get_sig_rnfe_2 = sm_client.get_secret_value(SecretId=sig_rnfe_2)
        assert get_sig_rnfe_2["Name"] == sig_rnfe_2
        assert get_sig_rnfe_2["SecretString"] == sig_rnfe_2

        get_res = sm_client.get_secret_value(SecretId=secret_name)
        assert get_res["VersionId"] == version_id_2
        secret_string_2 = lambda_rotate_secret.secret_of_rotation_from_version_id(version_id_2)
        assert get_res["SecretString"] == secret_string_2

        # clean up
        sm_client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
        testutil.delete_lambda_function(function_name)

    def test_rotate_secret_invalid_lambda_arn(self, sm_client):
        secret_name = f"s-{short_uid()}"
        sm_client.create_secret(Name=secret_name, SecretString="init")
        invalid_arn = (
            "arn:aws:lambda:sa-east-1:000000000000:function:rotate_secret_invalid_lambda_arn"
        )
        with pytest.raises(Exception) as res_not_found_ex:
            sm_client.rotate_secret(
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

        des = sm_client.describe_secret(SecretId=secret_name)
        assert "RotationEnabled" not in des
        assert "RotationRules" not in des
        assert "RotationLambdaARN" not in des

    def test_put_secret_value_with_version_stages(self, sm_client, sm_snapshot):
        secret_name = f"s-{short_uid()}"
        secret_string_v0: str = "secret_string_v0"

        create_secret_rs_0: CreateSecretResponse = self._typed_response_of(
            typ=CreateSecretResponse,
            response=sm_client.create_secret(Name=secret_name, SecretString=secret_string_v0),
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_rs_0, 0)
        )
        sm_snapshot.match("create_secret_rs_0", create_secret_rs_0)

        get_secret_value_res_0: GetSecretValueResponse = self._typed_response_of(
            typ=GetSecretValueResponse, response=sm_client.get_secret_value(SecretId=secret_name)
        )
        sm_snapshot.match("get_secret_value_res_0", get_secret_value_res_0)

        secret_string_v1: str = "secret_string_v1"
        version_stages_v1: List[str] = ["SAMPLESTAGE1", "SAMPLESTAGE0"]
        pv_v1_vid: str = str(uuid.uuid4())
        #
        put_secret_value_res_1: PutSecretValueResponse = self._typed_response_of(
            typ=PutSecretValueResponse,
            response=sm_client.put_secret_value(
                SecretId=secret_name,
                SecretString=secret_string_v1,
                VersionStages=version_stages_v1,
                ClientRequestToken=pv_v1_vid,
            ),
        )
        sm_snapshot.match("put_secret_value_res_1", put_secret_value_res_1)

        get_secret_value_res_1: GetSecretValueResponse = self._typed_response_of(
            typ=GetSecretValueResponse, response=sm_client.get_secret_value(SecretId=secret_name)
        )
        sm_snapshot.match("get_secret_value_res_1", get_secret_value_res_1)

        secret_string_v2: str = "secret_string_v2"
        version_stages_v2: ["str"] = version_stages_v1
        pv_v2_vid: str = str(uuid.uuid4())
        #
        put_secret_value_res_2: PutSecretValueResponse = self._typed_response_of(
            typ=PutSecretValueResponse,
            response=sm_client.put_secret_value(
                SecretId=secret_name,
                SecretString=secret_string_v2,
                VersionStages=version_stages_v2,
                ClientRequestToken=pv_v2_vid,
            ),
        )
        sm_snapshot.match("put_secret_value_res_2", put_secret_value_res_2)

        get_secret_value_res_2: GetSecretValueResponse = self._typed_response_of(
            typ=GetSecretValueResponse, response=sm_client.get_secret_value(SecretId=secret_name)
        )
        sm_snapshot.match("get_secret_value_res_2", get_secret_value_res_2)

        secret_string_v3: str = "secret_string_v3"
        version_stages_v3: ["str"] = ["AWSPENDING"]
        pv_v3_vid: str = str(uuid.uuid4())
        #
        put_secret_value_res_3: PutSecretValueResponse = self._typed_response_of(
            typ=PutSecretValueResponse,
            response=sm_client.put_secret_value(
                SecretId=secret_name,
                SecretString=secret_string_v3,
                VersionStages=version_stages_v3,
                ClientRequestToken=pv_v3_vid,
            ),
        )
        sm_snapshot.match("put_secret_value_res_3", put_secret_value_res_3)

        get_secret_value_res_3: GetSecretValueResponse = self._typed_response_of(
            typ=GetSecretValueResponse, response=sm_client.get_secret_value(SecretId=secret_name)
        )
        sm_snapshot.match("get_secret_value_res_3", get_secret_value_res_3)

        secret_string_v4: str = "secret_string_v4"
        pv_v4_vid: str = str(uuid.uuid4())
        #
        put_secret_value_res_4: PutSecretValueResponse = self._typed_response_of(
            typ=PutSecretValueResponse,
            response=sm_client.put_secret_value(
                SecretId=secret_name, SecretString=secret_string_v4, ClientRequestToken=pv_v4_vid
            ),
        )
        sm_snapshot.match("put_secret_value_res_4", put_secret_value_res_4)

        get_secret_value_res_4: GetSecretValueResponse = self._typed_response_of(
            typ=GetSecretValueResponse, response=sm_client.get_secret_value(SecretId=secret_name)
        )
        sm_snapshot.match("get_secret_value_res_4", get_secret_value_res_4)

        delete_secret_res_1: DeleteSecretResponse = self._typed_response_of(
            typ=DeleteSecretResponse,
            response=sm_client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True),
        )
        sm_snapshot.match("delete_secret_res_1", delete_secret_res_1)

    @pytest.mark.parametrize(
        "secret_name", ["Inv Name", " Inv Name", " Inv*Name? ", " Inv *?!]Name\\-"]
    )
    @pytest.mark.aws_validated
    def test_invalid_secret_name(self, sm_client, secret_name: str):
        def check_validation_exception(exc_info: ExceptionInfo):
            error = exc_info.value.response["Error"]
            error_code = error["Code"]
            error_msg = error["Message"]
            assert error_code == "ValidationException"
            assert (
                error_msg
                == "Invalid name. Must be a valid name containing alphanumeric characters, or any of the following: -/_+=.@!"
            )

        # The secret name can contain ASCII letters, numbers, and the following characters: /_+=.@-
        with pytest.raises(Exception) as validation_exception:
            sm_client.create_secret(Name=secret_name, SecretString="MySecretString")
        check_validation_exception(validation_exception)

        with pytest.raises(Exception) as validation_exception:
            sm_client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
        check_validation_exception(validation_exception)

        with pytest.raises(Exception) as validation_exception:
            sm_client.describe_secret(SecretId=secret_name)
        check_validation_exception(validation_exception)

        with pytest.raises(Exception) as validation_exception:
            sm_client.get_secret_value(SecretId=secret_name)
        check_validation_exception(validation_exception)

        with pytest.raises(Exception) as validation_exception:
            sm_client.list_secret_version_ids(SecretId=secret_name, IncludeDeprecated=True)
        check_validation_exception(validation_exception)

        with pytest.raises(Exception) as validation_exception:
            sm_client.put_secret_value(SecretId=secret_name, SecretString="MySecretString")
        check_validation_exception(validation_exception)

        with pytest.raises(Exception) as validation_exception:
            sm_client.tag_resource(
                SecretId=secret_name, Tags=[{"Key": "FirstTag", "Value": "SomeValue"}]
            )
        check_validation_exception(validation_exception)

        with pytest.raises(Exception) as validation_exception:
            sm_client.untag_resource(SecretId=secret_name, TagKeys=["FirstTag"])
        check_validation_exception(validation_exception)

        with pytest.raises(Exception) as validation_exception:
            sm_client.update_secret(SecretId=secret_name, Description="MyNewDescription")
        check_validation_exception(validation_exception)

        with pytest.raises(Exception) as validation_exception:
            sm_client.validate_resource_policy(
                SecretId=secret_name,
                ResourcePolicy='{\n"Version":"2012-10-17",\n"Statement":[{\n"Effect":"Allow",\n"Principal":{\n"AWS":"arn:aws:iam::123456789012:root"\n},\n"Action":"secretsmanager:GetSecretValue",\n"Resource":"*"\n}]\n}',
            )
        check_validation_exception(validation_exception)

    def test_last_accessed_date(self, sm_client):
        def last_accessed_scenario_1(fail_if_days_overlap: bool) -> bool:
            secret_name = f"s-{short_uid()}"

            sm_client.create_secret(Name=secret_name, SecretString="MySecretValue")

            des = sm_client.describe_secret(SecretId=secret_name)
            assert "LastAccessedDate" not in des

            t0 = today_no_time()

            sm_client.get_secret_value(SecretId=secret_name)
            des = sm_client.describe_secret(SecretId=secret_name)
            assert "LastAccessedDate" in des
            lad_v0 = des["LastAccessedDate"]
            assert isinstance(lad_v0, datetime)

            sm_client.get_secret_value(SecretId=secret_name)
            des = sm_client.describe_secret(SecretId=secret_name)
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

    def test_last_updated_date(self, sm_client):
        secret_name = f"s-{short_uid()}"
        sm_client.create_secret(Name=secret_name, SecretString="MySecretValue")

        res = sm_client.describe_secret(SecretId=secret_name)
        assert "LastChangedDate" in res
        create_date = res["LastChangedDate"]
        assert isinstance(create_date, datetime)

        res = sm_client.get_secret_value(SecretId=secret_name)
        assert create_date == res["CreatedDate"]

        res = sm_client.describe_secret(SecretId=secret_name)
        assert "LastChangedDate" in res
        assert create_date == res["LastChangedDate"]

        sm_client.update_secret(SecretId=secret_name, SecretString="MyNewSecretValue")

        res = sm_client.describe_secret(SecretId=secret_name)
        assert "LastChangedDate" in res
        assert create_date < res["LastChangedDate"]
        last_changed = res["LastChangedDate"]

        sm_client.update_secret(SecretId=secret_name, SecretString="MyNewSecretValue")

        res = sm_client.describe_secret(SecretId=secret_name)
        assert "LastChangedDate" in res
        assert last_changed < res["LastChangedDate"]

        sm_client.update_secret(SecretId=secret_name, SecretString="MyVeryNewSecretValue")

        res = sm_client.describe_secret(SecretId=secret_name)
        assert "LastChangedDate" in res
        assert create_date < res["LastChangedDate"]

    def test_update_secret_description(self, sm_client):
        secret_name = f"s-{short_uid()}"
        secret_string_v0 = "MySecretString"
        sm_client.create_secret(Name=secret_name, SecretString=secret_string_v0)

        des = sm_client.describe_secret(SecretId=secret_name)
        assert "Description" not in des

        description_v1 = "MyDescription"
        sm_client.update_secret(SecretId=secret_name, Description=description_v1)

        des = sm_client.describe_secret(SecretId=secret_name)
        assert des["Description"] == description_v1

        description_v2 = "MyNewDescription"
        secret_string_v1 = "MyNewSecretString"
        sm_client.update_secret(
            SecretId=secret_name, SecretString=secret_string_v1, Description=description_v2
        )

        des = sm_client.describe_secret(SecretId=secret_name)
        assert des["Description"] == description_v2

        sm_client.update_secret(SecretId=secret_name, SecretString=secret_string_v1 * 2)
        des = sm_client.describe_secret(SecretId=secret_name)
        assert des["Description"] == description_v2

    def test_update_secret_version_stages_return_type(self, sm_client):
        secret_name = f"s-{short_uid()}"
        create = sm_client.create_secret(Name=secret_name, SecretString="Something1")
        version_id_v0 = create["VersionId"]

        put_pending_res = sm_client.put_secret_value(
            SecretId=secret_name, SecretString="Something2", VersionStages=["AWSPENDING"]
        )
        version_id_v1 = put_pending_res["VersionId"]
        assert version_id_v1 != version_id_v0

        upd_res = sm_client.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=version_id_v0,
            MoveToVersionId=version_id_v1,
            VersionStage="AWSCURRENT",
        )
        assert upd_res.keys() == {"Name", "ARN", "ResponseMetadata"}
        assert upd_res["Name"] == create["Name"]
        assert upd_res["ARN"] == create["ARN"]

    def test_update_secret_version_stages_current_previous(self, sm_client):
        secret_name = f"s-{short_uid()}"
        secret_string_v0 = "secret_string_v0"
        create = sm_client.create_secret(Name=secret_name, SecretString=secret_string_v0)
        version_id_v0 = create["VersionId"]

        lst_ids_v0 = sm_client.list_secret_version_ids(SecretId=secret_name)
        versions_v0 = lst_ids_v0["Versions"]
        assert len(versions_v0) == 1
        versions_v0_v0 = versions_v0[0]
        assert versions_v0_v0["VersionId"] == version_id_v0
        assert versions_v0_v0["VersionStages"] == ["AWSCURRENT"]

        secret_string_v1 = "secret_string_v1"
        update_v1 = sm_client.update_secret(SecretId=secret_name, SecretString=secret_string_v1)
        version_id_v1 = update_v1["VersionId"]
        assert version_id_v0 != version_id_v1

        lst_ids_v1 = sm_client.list_secret_version_ids(SecretId=secret_name)
        versions_v1 = lst_ids_v1["Versions"]
        assert len(versions_v1) == 2
        versions_v1_v0 = versions_v1[0]
        assert versions_v1_v0["VersionId"] == version_id_v0
        assert versions_v1_v0["VersionStages"] == ["AWSPREVIOUS"]
        versions_v1_v1 = versions_v1[1]
        assert versions_v1_v1["VersionId"] == version_id_v1
        assert versions_v1_v1["VersionStages"] == ["AWSCURRENT"]

    def test_update_secret_version_stages_current_pending(self, sm_client):
        secret_name = f"s-{short_uid()}"
        create = sm_client.create_secret(Name=secret_name, SecretString="Something1")
        version_id_v0 = create["VersionId"]

        put_pending_res = sm_client.put_secret_value(
            SecretId=secret_name, SecretString="Something2", VersionStages=["AWSPENDING"]
        )
        version_id_v1 = put_pending_res["VersionId"]
        assert version_id_v1 != version_id_v0

        list_ids_res = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(list_ids_res["Versions"]) == 2
        list_ids_0 = list_ids_res["Versions"][0]
        assert list_ids_0["VersionId"] == version_id_v0
        assert list_ids_0["VersionStages"] == ["AWSCURRENT"]
        list_ids_1 = list_ids_res["Versions"][1]
        assert list_ids_1["VersionId"] == version_id_v1
        assert list_ids_1["VersionStages"] == ["AWSPENDING"]

        upd_res = sm_client.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=version_id_v0,
            MoveToVersionId=version_id_v1,
            VersionStage="AWSCURRENT",
        )
        assert "VersionId" not in upd_res

        list_ids_2_res = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(list_ids_2_res["Versions"]) == 2
        list_ids_2_0 = list_ids_2_res["Versions"][0]
        assert list_ids_2_0["VersionId"] == version_id_v0
        assert list_ids_2_0["VersionStages"] == ["AWSPREVIOUS"]
        list_ids_2_1 = list_ids_2_res["Versions"][1]
        assert list_ids_2_1["VersionId"] == version_id_v1
        assert list_ids_2_1["VersionStages"] == ["AWSPENDING", "AWSCURRENT"]

        upd_2_res = sm_client.put_secret_value(SecretId=secret_name, SecretString="SS3")
        version_id_v2 = upd_2_res["VersionId"]
        assert len({version_id_v0, version_id_v1, version_id_v2}) == 3

        list_ids_3_res = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(list_ids_3_res["Versions"]) == 2
        list_ids_3_0 = list_ids_3_res["Versions"][0]
        assert list_ids_3_0["VersionId"] == version_id_v1
        assert list_ids_3_0["VersionStages"] == ["AWSPREVIOUS"]
        list_ids_3_1 = list_ids_3_res["Versions"][1]
        assert list_ids_3_1["VersionId"] == version_id_v2
        assert list_ids_3_1["VersionStages"] == ["AWSCURRENT"]

    def test_update_secret_version_stages_current_pending_cycle(self, sm_client):
        secret_name = f"s-{short_uid()}"
        create = sm_client.create_secret(Name=secret_name, SecretString="S1")
        vid_0 = create["VersionId"]

        put_1 = sm_client.put_secret_value(
            SecretId=secret_name, SecretString="S2", VersionStages=["AWSPENDING"]
        )
        vid_1 = put_1["VersionId"]
        assert vid_1 != vid_0

        lst_1 = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_1["Versions"]) == 2
        #
        lst_1_v_0 = lst_1["Versions"][0]
        assert lst_1_v_0["VersionId"] == vid_0
        assert lst_1_v_0["VersionStages"] == ["AWSCURRENT"]
        #
        lst_1_v_1 = lst_1["Versions"][1]
        assert lst_1_v_1["VersionId"] == vid_1
        assert lst_1_v_1["VersionStages"] == ["AWSPENDING"]

        get_1 = sm_client.get_secret_value(SecretId=secret_name)
        assert get_1["VersionId"] == vid_0
        assert get_1["SecretString"] == "S1"
        assert get_1["VersionStages"] == ["AWSCURRENT"]

        upd_1 = sm_client.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=vid_0,
            MoveToVersionId=vid_1,
            VersionStage="AWSCURRENT",
        )
        assert "VersionId" not in upd_1

        lst_1_u = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_1_u["Versions"]) == 2
        #
        lst_1_u_v_0 = lst_1_u["Versions"][0]
        assert lst_1_u_v_0["VersionId"] == vid_0
        assert lst_1_u_v_0["VersionStages"] == ["AWSPREVIOUS"]
        #
        lst_1_u_v_1 = lst_1_u["Versions"][1]
        assert lst_1_u_v_1["VersionId"] == vid_1
        assert lst_1_u_v_1["VersionStages"] == ["AWSPENDING", "AWSCURRENT"]

        get_1_u = sm_client.get_secret_value(SecretId=secret_name)
        assert get_1_u["VersionId"] == vid_1
        assert get_1_u["SecretString"] == "S2"
        assert get_1_u["VersionStages"] == ["AWSPENDING", "AWSCURRENT"]

        put_2 = sm_client.put_secret_value(
            SecretId=secret_name, SecretString="S3", VersionStages=["AWSPENDING"]
        )
        vid_2 = put_2["VersionId"]
        assert len({vid_0, vid_1, vid_2}) == 3

        lst_2 = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_2["Versions"]) == 3
        #
        lst_2_v_0 = lst_2["Versions"][0]
        assert lst_2_v_0["VersionId"] == vid_0
        assert lst_2_v_0["VersionStages"] == ["AWSPREVIOUS"]
        #
        lst_2_v_1 = lst_2["Versions"][1]
        assert lst_2_v_1["VersionId"] == vid_1
        assert lst_2_v_1["VersionStages"] == ["AWSCURRENT"]
        #
        lst_2_v_2 = lst_2["Versions"][2]
        assert lst_2_v_2["VersionId"] == vid_2
        assert lst_2_v_2["VersionStages"] == ["AWSPENDING"]

        get_2 = sm_client.get_secret_value(SecretId=secret_name)
        assert get_2["VersionId"] == vid_1
        assert get_2["SecretString"] == "S2"
        assert get_2["VersionStages"] == ["AWSCURRENT"]

        upd_2 = sm_client.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=vid_1,
            MoveToVersionId=vid_2,
            VersionStage="AWSCURRENT",
        )
        assert "VersionId" not in upd_2

        lst_2_u = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_2_u["Versions"]) == 2
        #
        lst_2_u_v_0 = lst_2_u["Versions"][0]
        assert lst_2_u_v_0["VersionId"] == vid_1
        assert lst_2_u_v_0["VersionStages"] == ["AWSPREVIOUS"]
        #
        lst_2_u_v_1 = lst_2_u["Versions"][1]
        assert lst_2_u_v_1["VersionId"] == vid_2
        assert lst_2_u_v_1["VersionStages"] == ["AWSPENDING", "AWSCURRENT"]

        get_1_u = sm_client.get_secret_value(SecretId=secret_name)
        assert get_1_u["VersionId"] == vid_2
        assert get_1_u["SecretString"] == "S3"
        assert get_1_u["VersionStages"] == ["AWSPENDING", "AWSCURRENT"]

    def test_update_secret_version_stages_current_pending_cycle_custom_stages_1(self, sm_client):
        secret_name = f"s-{short_uid()}"
        create = sm_client.create_secret(Name=secret_name, SecretString="S1")
        vid_0 = create["VersionId"]

        put_1 = sm_client.put_secret_value(
            SecretId=secret_name, SecretString="S2", VersionStages=["AWSPENDING", "PUT1"]
        )
        vid_1 = put_1["VersionId"]
        assert vid_1 != vid_0

        lst_1 = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_1["Versions"]) == 2
        #
        lst_1_v_0 = lst_1["Versions"][0]
        assert lst_1_v_0["VersionId"] == vid_0
        assert lst_1_v_0["VersionStages"] == ["AWSCURRENT"]
        #
        lst_1_v_1 = lst_1["Versions"][1]
        assert lst_1_v_1["VersionId"] == vid_1
        assert lst_1_v_1["VersionStages"] == ["AWSPENDING", "PUT1"]

        get_1 = sm_client.get_secret_value(SecretId=secret_name)
        assert get_1["VersionId"] == vid_0
        assert get_1["SecretString"] == "S1"
        assert get_1["VersionStages"] == ["AWSCURRENT"]

        upd_1 = sm_client.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=vid_0,
            MoveToVersionId=vid_1,
            VersionStage="AWSCURRENT",
        )
        assert "VersionId" not in upd_1

        lst_1_u = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_1_u["Versions"]) == 2
        #
        lst_1_u_v_0 = lst_1_u["Versions"][0]
        assert lst_1_u_v_0["VersionId"] == vid_0
        assert lst_1_u_v_0["VersionStages"] == ["AWSPREVIOUS"]
        #
        lst_1_u_v_1 = lst_1_u["Versions"][1]
        assert lst_1_u_v_1["VersionId"] == vid_1
        assert lst_1_u_v_1["VersionStages"] == ["AWSPENDING", "PUT1", "AWSCURRENT"]

        get_1_u = sm_client.get_secret_value(SecretId=secret_name)
        assert get_1_u["VersionId"] == vid_1
        assert get_1_u["SecretString"] == "S2"
        assert get_1_u["VersionStages"] == ["AWSPENDING", "PUT1", "AWSCURRENT"]

        put_2 = sm_client.put_secret_value(
            SecretId=secret_name, SecretString="S3", VersionStages=["AWSPENDING", "PUT2"]
        )
        vid_2 = put_2["VersionId"]
        assert len({vid_0, vid_1, vid_2}) == 3

        lst_2 = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_2["Versions"]) == 3
        #
        lst_2_v_0 = lst_2["Versions"][0]
        assert lst_2_v_0["VersionId"] == vid_0
        assert lst_2_v_0["VersionStages"] == ["AWSPREVIOUS"]
        #
        lst_2_v_1 = lst_2["Versions"][1]
        assert lst_2_v_1["VersionId"] == vid_1
        assert lst_2_v_1["VersionStages"] == ["PUT1", "AWSCURRENT"]
        #
        lst_2_v_2 = lst_2["Versions"][2]
        assert lst_2_v_2["VersionId"] == vid_2
        assert lst_2_v_2["VersionStages"] == ["AWSPENDING", "PUT2"]

        get_2 = sm_client.get_secret_value(SecretId=secret_name)
        assert get_2["VersionId"] == vid_1
        assert get_2["SecretString"] == "S2"
        assert get_2["VersionStages"] == ["PUT1", "AWSCURRENT"]

        upd_2 = sm_client.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=vid_1,
            MoveToVersionId=vid_2,
            VersionStage="AWSCURRENT",
        )
        assert "VersionId" not in upd_2

        lst_2_u = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_2_u["Versions"]) == 2
        #
        lst_2_u_v_0 = lst_2_u["Versions"][0]
        assert lst_2_u_v_0["VersionId"] == vid_1
        assert lst_2_u_v_0["VersionStages"] == ["PUT1", "AWSPREVIOUS"]
        #
        lst_2_u_v_1 = lst_2_u["Versions"][1]
        assert lst_2_u_v_1["VersionId"] == vid_2
        assert lst_2_u_v_1["VersionStages"] == ["AWSPENDING", "PUT2", "AWSCURRENT"]

        get_1_u = sm_client.get_secret_value(SecretId=secret_name)
        assert get_1_u["VersionId"] == vid_2
        assert get_1_u["SecretString"] == "S3"
        assert get_1_u["VersionStages"] == ["AWSPENDING", "PUT2", "AWSCURRENT"]

    def test_update_secret_version_stages_current_pending_cycle_custom_stages_2(self, sm_client):
        secret_name = f"s-{short_uid()}"
        create = sm_client.create_secret(Name=secret_name, SecretString="SS")
        vid_s = create["VersionId"]

        put_0 = sm_client.put_secret_value(
            SecretId=secret_name, SecretString="S1", VersionStages=["AWSCURRENT", "PUT0"]
        )
        vid_0 = put_0["VersionId"]
        assert vid_0 != vid_s

        lst_0 = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_0["Versions"]) == 2
        #
        lst_0_v_s = lst_0["Versions"][0]
        assert lst_0_v_s["VersionId"] == vid_s
        assert lst_0_v_s["VersionStages"] == ["AWSPREVIOUS"]
        #
        lst_0_v_0 = lst_0["Versions"][1]
        assert lst_0_v_0["VersionId"] == vid_0
        assert lst_0_v_0["VersionStages"] == ["AWSCURRENT", "PUT0"]

        put_1 = sm_client.put_secret_value(
            SecretId=secret_name, SecretString="S2", VersionStages=["AWSPENDING", "PUT1"]
        )
        vid_1 = put_1["VersionId"]
        assert len({vid_s, vid_0, vid_1}) == 3

        lst_1 = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_1["Versions"]) == 3
        #
        lst_1_v_s = lst_1["Versions"][0]
        assert lst_1_v_s["VersionId"] == vid_s
        assert lst_1_v_s["VersionStages"] == ["AWSPREVIOUS"]
        #
        lst_1_v_0 = lst_1["Versions"][1]
        assert lst_1_v_0["VersionId"] == vid_0
        assert lst_1_v_0["VersionStages"] == ["AWSCURRENT", "PUT0"]
        #
        lst_1_v_1 = lst_1["Versions"][2]
        assert lst_1_v_1["VersionId"] == vid_1
        assert lst_1_v_1["VersionStages"] == ["AWSPENDING", "PUT1"]

        get_1 = sm_client.get_secret_value(SecretId=secret_name)
        assert get_1["VersionId"] == vid_0
        assert get_1["SecretString"] == "S1"
        assert get_1["VersionStages"] == ["AWSCURRENT", "PUT0"]

        upd_1 = sm_client.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=vid_0,
            MoveToVersionId=vid_1,
            VersionStage="AWSCURRENT",
        )
        assert "VersionId" not in upd_1

        lst_1_u = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_1_u["Versions"]) == 2
        #
        lst_1_u_v_0 = lst_1_u["Versions"][0]
        assert lst_1_u_v_0["VersionId"] == vid_0
        assert lst_1_u_v_0["VersionStages"] == ["PUT0", "AWSPREVIOUS"]
        #
        lst_1_u_v_1 = lst_1_u["Versions"][1]
        assert lst_1_u_v_1["VersionId"] == vid_1
        assert lst_1_u_v_1["VersionStages"] == ["AWSPENDING", "PUT1", "AWSCURRENT"]

        get_1_u = sm_client.get_secret_value(SecretId=secret_name)
        assert get_1_u["VersionId"] == vid_1
        assert get_1_u["SecretString"] == "S2"
        assert get_1_u["VersionStages"] == ["AWSPENDING", "PUT1", "AWSCURRENT"]

        put_2 = sm_client.put_secret_value(
            SecretId=secret_name, SecretString="S3", VersionStages=["AWSPENDING", "PUT2"]
        )
        vid_2 = put_2["VersionId"]
        assert len({vid_s, vid_0, vid_1, vid_2}) == 4

        lst_2 = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_2["Versions"]) == 3
        #
        lst_2_v_0 = lst_2["Versions"][0]
        assert lst_2_v_0["VersionId"] == vid_0
        assert lst_2_v_0["VersionStages"] == ["PUT0", "AWSPREVIOUS"]
        #
        lst_2_v_1 = lst_2["Versions"][1]
        assert lst_2_v_1["VersionId"] == vid_1
        assert lst_2_v_1["VersionStages"] == ["PUT1", "AWSCURRENT"]
        #
        lst_2_v_2 = lst_2["Versions"][2]
        assert lst_2_v_2["VersionId"] == vid_2
        assert lst_2_v_2["VersionStages"] == ["AWSPENDING", "PUT2"]

        get_2 = sm_client.get_secret_value(SecretId=secret_name)
        assert get_2["VersionId"] == vid_1
        assert get_2["SecretString"] == "S2"
        assert get_2["VersionStages"] == ["PUT1", "AWSCURRENT"]

        upd_2 = sm_client.update_secret_version_stage(
            SecretId=secret_name,
            RemoveFromVersionId=vid_1,
            MoveToVersionId=vid_2,
            VersionStage="AWSCURRENT",
        )
        assert "VersionId" not in upd_2

        lst_2_u = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_2_u["Versions"]) == 3
        #
        lst_2_u_v_0 = lst_2_u["Versions"][0]
        assert lst_2_u_v_0["VersionId"] == vid_0
        assert lst_2_u_v_0["VersionStages"] == ["PUT0"]
        #
        lst_2_u_v_1 = lst_2_u["Versions"][1]
        assert lst_2_u_v_1["VersionId"] == vid_1
        assert lst_2_u_v_1["VersionStages"] == ["PUT1", "AWSPREVIOUS"]
        #
        lst_2_u_v_2 = lst_2_u["Versions"][2]
        assert lst_2_u_v_2["VersionId"] == vid_2
        assert lst_2_u_v_2["VersionStages"] == ["AWSPENDING", "PUT2", "AWSCURRENT"]
        #
        get_1_u = sm_client.get_secret_value(SecretId=secret_name)
        assert get_1_u["VersionId"] == vid_2
        assert get_1_u["SecretString"] == "S3"
        assert get_1_u["VersionStages"] == ["AWSPENDING", "PUT2", "AWSCURRENT"]

    def test_non_versioning_version_stages_replacement(self, sm_client):
        secret_name = f"s-{short_uid()}"
        create = sm_client.create_secret(Name=secret_name, SecretString="S0")
        vid_s = create["VersionId"]

        put_0 = sm_client.put_secret_value(
            SecretId=secret_name, SecretString="S1", VersionStages=["one", "two", "three"]
        )
        vid_0 = put_0["VersionId"]
        assert vid_0 != vid_s

        lst_0 = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_0["Versions"]) == 2
        #
        lst_0_v_0 = lst_0["Versions"][0]
        assert lst_0_v_0["VersionId"] == vid_s
        assert lst_0_v_0["VersionStages"] == ["AWSCURRENT"]
        #
        lst_0_v_1 = lst_0["Versions"][1]
        assert lst_0_v_1["VersionId"] == vid_0
        assert lst_0_v_1["VersionStages"] == ["one", "two", "three"]

        put_1 = sm_client.put_secret_value(
            SecretId=secret_name, SecretString="S2", VersionStages=["one", "two", "three", "four"]
        )
        vid_1 = put_1["VersionId"]
        assert len({vid_s, vid_0, vid_1}) == 3

        lst_1 = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_1["Versions"]) == 2
        #
        lst_1_v_0 = lst_1["Versions"][0]
        assert lst_1_v_0["VersionId"] == vid_s
        assert lst_1_v_0["VersionStages"] == ["AWSCURRENT"]
        #
        lst_1_v_1 = lst_1["Versions"][1]
        assert lst_1_v_1["VersionId"] == vid_1
        assert lst_1_v_1["VersionStages"] == ["one", "two", "three", "four"]

    def test_non_versioning_version_stages_no_replacement(self, sm_client):
        secret_name = f"s-{short_uid()}"
        create = sm_client.create_secret(Name=secret_name, SecretString="S0")
        vid_s = create["VersionId"]

        put_0 = sm_client.put_secret_value(
            SecretId=secret_name, SecretString="S1", VersionStages=["one", "two", "three"]
        )
        vid_0 = put_0["VersionId"]
        assert vid_0 != vid_s

        lst_0 = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_0["Versions"]) == 2
        #
        lst_0_v_0 = lst_0["Versions"][0]
        assert lst_0_v_0["VersionId"] == vid_s
        assert lst_0_v_0["VersionStages"] == ["AWSCURRENT"]
        #
        lst_0_v_1 = lst_0["Versions"][1]
        assert lst_0_v_1["VersionId"] == vid_0
        assert lst_0_v_1["VersionStages"] == ["one", "two", "three"]

        put_1 = sm_client.put_secret_value(
            SecretId=secret_name, SecretString="S2", VersionStages=["one", "two", "four"]
        )
        vid_1 = put_1["VersionId"]
        assert len({vid_s, vid_0, vid_1}) == 3

        lst_1 = sm_client.list_secret_version_ids(SecretId=secret_name)
        assert len(lst_1["Versions"]) == 3
        #
        lst_1_v_0 = lst_1["Versions"][0]
        assert lst_1_v_0["VersionId"] == vid_s
        assert lst_1_v_0["VersionStages"] == ["AWSCURRENT"]
        #
        lst_1_v_1 = lst_1["Versions"][1]
        assert lst_1_v_1["VersionId"] == vid_0
        assert lst_1_v_1["VersionStages"] == ["three"]
        #
        lst_1_v_2 = lst_1["Versions"][2]
        assert lst_1_v_2["VersionId"] == vid_1
        assert lst_1_v_2["VersionStages"] == ["one", "two", "four"]

    @staticmethod
    def secretsmanager_http_json_headers(amz_target: str) -> Dict:
        headers = aws_stack.mock_aws_request_headers("secretsmanager")
        headers["X-Amz-Target"] = amz_target
        return headers

    def secretsmanager_http_json_post(self, amz_target: str, http_body: json) -> requests.Response:
        ep_url: str = aws_stack.get_local_service_url("secretsmanager")
        http_headers: Dict = self.secretsmanager_http_json_headers(amz_target)
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
        version_stages: List[str],
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
        version_stages: List[str],
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

    def test_http_update_secret_with_missing_client_request_token(self):
        secret_name = f"s-{short_uid()}"

        # Create v0.
        secret_string_v0: str = "secret_string_v0"
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0),
            secret_name,
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

        # Update without client request token.
        secret_string_v2: str = "secret_string_v2"
        res_update_json = self.secretsmanager_http_update_secret_val_res(
            self.secretsmanager_http_update_secret(secret_name, secret_string_v2, None),
            secret_name,
            None,
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

    def test_http_put_secret_value_with_new_custom_client_request_token(self):
        secret_name = f"s-{short_uid()}"

        # Create v0.
        secret_string_v0: str = "MySecretString"
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0),
            secret_name,
        )
        #
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

    def test_http_put_secret_value_with_duplicate_client_request_token(self):
        secret_name = f"s-{short_uid()}"

        # Create v0.
        secret_string_v0: str = "MySecretString"
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0),
            secret_name,
        )
        #
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

    def test_http_put_secret_value_with_null_client_request_token(self):
        secret_name = f"s-{short_uid()}"

        # Create v0.
        secret_string_v0: str = "MySecretString"
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0),
            secret_name,
        )
        #
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json["VersionId"],
        )

        # Update v0 with null ClientRequestToken.
        secret_string_v1: str = "MyNewSecretString"
        #
        pv_v1_res_json = self.secretsmanager_http_put_secret_value_val_res(
            self.secretsmanager_http_put_secret_value_with(secret_name, secret_string_v1, None),
            secret_name,
        )
        #
        # Check v1 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v1,
            pv_v1_res_json["VersionId"],
        )
        #
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

    def test_http_put_secret_value_with_undefined_client_request_token(self):
        secret_name = f"s-{short_uid()}"

        # Create v0.
        secret_string_v0: str = "MySecretString"
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0),
            secret_name,
        )
        #
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json["VersionId"],
        )

        # Update v0 with undefined ClientRequestToken.
        secret_string_v1: str = "MyNewSecretString"
        #
        pv_v1_res_json = self.secretsmanager_http_put_secret_value_val_res(
            self.secretsmanager_http_put_secret_value(secret_name, secret_string_v1), secret_name
        )
        #
        # Check v1 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v1,
            pv_v1_res_json["VersionId"],
        )
        #
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

    def test_http_put_secret_value_duplicate_req(self):
        secret_name = f"s-{short_uid()}"

        # Create v0.
        secret_string_v0: str = "MySecretString"
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0),
            secret_name,
        )
        #
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

    def test_http_put_secret_value_null_client_request_token_new_version_stages(self):
        secret_name = f"s-{short_uid()}"

        # Create v0.
        secret_string_v0: str = "MySecretString"
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0),
            secret_name,
        )
        #
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json["VersionId"],
        )

        # Update v0 with null ClientRequestToken.
        secret_string_v1: str = "MyNewSecretString"
        version_stages_v1: List[str] = ["AWSPENDING"]
        #
        pv_v1_res_json = self.secretsmanager_http_put_secret_value_with_version_val_res(
            self.secretsmanager_http_put_secret_value_with_version(
                secret_name, secret_string_v1, None, version_stages_v1
            ),
            secret_name,
            None,
            version_stages_v1,
        )
        #
        assert pv_v1_res_json["VersionId"] != cr_v0_res_json["VersionId"]
        #
        # Check v1 base consistency.
        self.secretsmanager_http_get_secret_value_with_val_res(
            self.secretsmanager_http_get_secret_value_with(secret_name, "AWSPENDING"),
            secret_name,
            secret_string_v1,
            pv_v1_res_json["VersionId"],
            "AWSPENDING",
        )
        #
        # Check v0 base consistency.
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

    def test_http_put_secret_value_custom_client_request_token_new_version_stages(self):
        secret_name = f"s-{short_uid()}"

        # Create v0.
        secret_string_v0: str = "MySecretString"
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0),
            secret_name,
        )
        #
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json["VersionId"],
        )

        # Update v0 with null ClientRequestToken.
        secret_string_v1: str = "MyNewSecretString"
        version_stages_v1: List[str] = ["AWSPENDING"]
        crt_v1: str = str(uuid.uuid4())
        while crt_v1 == cr_v0_res_json["VersionId"]:
            crt_v1 = str(uuid.uuid4())
        #
        self.secretsmanager_http_put_secret_value_with_version_val_res(
            self.secretsmanager_http_put_secret_value_with_version(
                secret_name, secret_string_v1, crt_v1, version_stages_v1
            ),
            secret_name,
            crt_v1,
            version_stages_v1,
        )
        #
        # Check v1 base consistency.
        self.secretsmanager_http_get_secret_value_with_val_res(
            self.secretsmanager_http_get_secret_value_with(secret_name, "AWSPENDING"),
            secret_name,
            secret_string_v1,
            crt_v1,
            "AWSPENDING",
        )
        #
        # Check v0 base consistency.
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

    def test_delete_non_existent_secret_returns_as_if_secret_exists(self, sm_client):
        """When ForceDeleteWithoutRecovery=True, AWS responds as if the non-existent secret was successfully deleted."""
        secret_id = "non-existent-secret"

        response = sm_client.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)

        assert response["Name"] == secret_id
        assert response["ARN"] is not None
        assert response["DeletionDate"] is not None

    def test_exp_raised_on_creation_of_secret_scheduled_for_deletion(self, sm_client, sm_snapshot):
        create_secret_req: CreateSecretRequest = CreateSecretRequest(
            Name=f"secret-{short_uid()}", SecretString=f"secretstr-{short_uid()}"
        )
        stage_deletion_req: DeleteSecretRequest = DeleteSecretRequest(
            SecretId=create_secret_req["Name"], RecoveryWindowInDays=7
        )

        res = sm_client.create_secret(**create_secret_req)
        create_secret_res: CreateSecretResponse = select_from_typed_dict(CreateSecretResponse, res)
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_res, 0)
        )

        res = sm_client.delete_secret(**stage_deletion_req)
        delete_res: DeleteSecretResponse = select_from_typed_dict(DeleteSecretResponse, res)
        sm_snapshot.match("delete_res", delete_res)

        with pytest.raises(Exception) as invalid_req_ex:
            sm_client.create_secret(**create_secret_req)

        ex_log: Dict = self._snapshot_obj_of_exception(invalid_req_ex)
        sm_snapshot.match("invalid_req_ex", ex_log)

    def test_can_recreate_delete_secret(self, sm_client, sm_snapshot):
        # NOTE: AWS will behave as staged deletion for a small number of seconds (<10).
        # We assume forced deletion is instantaneous, until the precise behaviour is understood.

        create_secret_req: CreateSecretRequest = CreateSecretRequest(
            Name=f"secret-{short_uid()}", SecretString=f"secretstr-{short_uid()}"
        )
        stage_deletion_req: DeleteSecretRequest = DeleteSecretRequest(
            SecretId=create_secret_req["Name"], ForceDeleteWithoutRecovery=True
        )

        res = sm_client.create_secret(**create_secret_req)
        create_secret_res_0: CreateSecretResponse = select_from_typed_dict(
            CreateSecretResponse, res
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_res_0, 0)
        )
        sm_snapshot.match("create_secret_res_0", create_secret_res_0)

        res = sm_client.delete_secret(**stage_deletion_req)
        delete_res_1: DeleteSecretResponse = select_from_typed_dict(DeleteSecretResponse, res)
        sm_snapshot.match("delete_res_1", delete_res_1)

        self._wait_force_deletion_completed(sm_client, stage_deletion_req["SecretId"])

        res = sm_client.create_secret(**create_secret_req)
        create_secret_res_1: CreateSecretResponse = select_from_typed_dict(
            CreateSecretResponse, res
        )
        sm_snapshot.add_transformers_list(
            sm_snapshot.transform.secretsmanager_secret_id_arn(create_secret_res_1, 1)
        )
        sm_snapshot.match("create_secret_res_1", create_secret_res_1)

        sm_client.delete_secret(**stage_deletion_req)
