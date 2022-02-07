from typing import Optional
import json
import pytest
import requests
import uuid
from datetime import datetime

from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON36
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.strings import short_uid
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_PYTHON_VERSION

RESOURCE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::%s:root" % TEST_AWS_ACCOUNT_ID},
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "*",
        }
    ],
}


class TestSecretsManager:

    @pytest.fixture
    def secretsmanager_client(self):
        return aws_stack.create_external_boto_client("secretsmanager")

    def test_create_and_update_secret(self, secretsmanager_client):
        secret_name = "s-%s" % short_uid()
        rs = secretsmanager_client.create_secret(
            Name=secret_name,
            SecretString="my_secret",
            Description="testing creation of secrets",
        )
        secret_arn = rs["ARN"]

        assert 6 == len(secret_arn.rpartition("-")[2])

        rs = secretsmanager_client.get_secret_value(SecretId=secret_name)
        assert secret_name == rs['Name']
        assert 'my_secret' == rs['SecretString']
        assert secret_arn == rs['ARN']
        assert isinstance(rs['CreatedDate'], datetime)

        rs = secretsmanager_client.get_secret_value(SecretId=secret_arn)
        assert secret_name == rs['Name']
        assert 'my_secret' == rs['SecretString']
        assert secret_arn == rs['ARN']

        rs = secretsmanager_client.get_secret_value(SecretId=secret_arn[: len(secret_arn) - 6])
        assert secret_name == rs['Name']
        assert 'my_secret' == rs['SecretString']
        assert secret_arn == rs['ARN']

        rs = secretsmanager_client.get_secret_value(SecretId=secret_arn[: len(secret_arn) - 7])
        assert secret_name == rs['Name']
        assert 'my_secret' == rs['SecretString']
        assert secret_arn == rs['ARN']

        secretsmanager_client.put_secret_value(SecretId=secret_name, SecretString='new_secret')

        rs = secretsmanager_client.get_secret_value(SecretId=secret_name)
        assert secret_name == rs['Name']
        assert 'new_secret' == rs['SecretString']

        # update secret by ARN
        rs = secretsmanager_client.update_secret(
            SecretId=secret_arn, KmsKeyId='test123', Description='d1'
        )
        assert 200 == rs['ResponseMetadata']['HTTPStatusCode']
        assert secret_arn == rs['ARN']

        # clean up
        secretsmanager_client.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )

    def test_call_lists_secrets_multiple_time(self, secretsmanager_client):
        secret_name = "s-%s" % short_uid()
        secretsmanager_client.create_secret(
            Name=secret_name,
            SecretString='my_secret',
            Description='testing creation of secrets',
        )

        # call list_secrets multiple times
        for i in range(3):
            rs = secretsmanager_client.list_secrets()
            secrets = [secret for secret in rs['SecretList'] if secret['Name'] == secret_name]
            assert 1 == len(secrets)

        # clean up
        secretsmanager_client.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )

    def test_create_multi_secrets(self, secretsmanager_client):
        secret_names = [short_uid(), short_uid(), short_uid()]
        arns = []
        for secret_name in secret_names:
            rs = secretsmanager_client.create_secret(
                Name=secret_name,
                SecretString="my_secret_{}".format(secret_name),
                Description='testing creation of secrets',
            )
            arns.append(rs['ARN'])

        rs = secretsmanager_client.list_secrets()
        secrets = {
            secret['Name']: secret['ARN']
            for secret in rs['SecretList']
            if secret['Name'] in secret_names
        }

        assert len(secret_names) == len(secrets.keys())
        for arn in arns:
            assert arn in secrets.values()

        # clean up
        for secret_name in secret_names:
            secretsmanager_client.delete_secret(
                SecretId=secret_name, ForceDeleteWithoutRecovery=True
            )

    def test_get_random_exclude_characters_and_symbols(self, secretsmanager_client):
        random_password = secretsmanager_client.get_random_password(
            PasswordLength=120, ExcludeCharacters='xyzDje@?!.'
        )

        assert 120, len(random_password['RandomPassword'])
        assert all(c not in 'xyzDje@?!.' for c in random_password['RandomPassword'])

    def test_resource_policy(self, secretsmanager_client):
        secret_name = "s-%s" % short_uid()

        secretsmanager_client.create_secret(
            Name=secret_name,
            SecretString='my_secret',
            Description='testing creation of secrets',
        )

        secretsmanager_client.put_resource_policy(
            SecretId=secret_name, ResourcePolicy=json.dumps(RESOURCE_POLICY)
        )

        rs = secretsmanager_client.get_resource_policy(SecretId=secret_name)

        policy = json.loads(rs['ResourcePolicy'])

        assert RESOURCE_POLICY['Version'] == policy['Version']
        assert RESOURCE_POLICY['Statement'] == policy['Statement']

        rs = secretsmanager_client.delete_resource_policy(SecretId=secret_name)
        assert 200 == rs['ResponseMetadata']['HTTPStatusCode']

        # clean up
        secretsmanager_client.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )

    def test_rotate_secret_with_lambda(self, secretsmanager_client):
        secret_name = "s-%s" % short_uid()

        secretsmanager_client.create_secret(
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

        response = secretsmanager_client.rotate_secret(
            SecretId=secret_name,
            RotationLambdaARN=function_arn,
            RotationRules={
                "AutomaticallyAfterDays": 1,
            },
            RotateImmediately=True,
        )

        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # clean up
        self.secretsmanager_client.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )
        testutil.delete_lambda_function(function_name)

    @staticmethod
    def secretsmanager_http_json_headers(amz_target: str) -> dict[str, str]:
        region: str = aws_stack.get_region()
        return {
            'X-Amz-Target': f"{amz_target}",
            'Content-Type': 'application/x-amz-json-1.1',
            'Authorization': f"AWS4-HMAC-SHA256 Credential=test/20220202/{region}/secretsmanager/aws4_request, "
                             'SignedHeaders=content-type;host;x-amz-date;x-amz-target, '
                             'Signature=0c921412dc327a81fa7ee1199a69437285faef19d0764e4b7913c908ca053810'
        }

    def secretsmanager_http_json_post(self, amz_target: str, http_body: json) -> requests.Response:
        ep_url: str = aws_stack.get_local_service_url('secretsmanager')
        http_headers: dict[str, str] = self.secretsmanager_http_json_headers(amz_target)
        return requests.post(
            ep_url,
            headers=http_headers,
            data=json.dumps(http_body)
        )

    def secretsmanager_http_create_secret_string(self, secret_name: str, secret_string: str) -> requests.Response:
        http_body: json = {
            'Name': secret_name,
            'SecretString': secret_string
        }
        return self.secretsmanager_http_json_post('secretsmanager.CreateSecret', http_body)

    @staticmethod
    def secretsmanager_http_create_secret_string_val_res(res: requests.Response, secret_name: str) -> json:
        assert res.status_code == 200
        res_json: json = res.json()
        assert res_json['Name'] == secret_name
        return res_json

    def secretsmanager_http_get_secret_value(self, secret_id: str) -> requests.Response:
        http_body: json = {
            'SecretId': secret_id
        }
        return self.secretsmanager_http_json_post('secretsmanager.GetSecretValue', http_body)

    @staticmethod
    def secretsmanager_http_get_secret_value_val_res(
            res: requests.Response, secret_name: str, secret_string: str, version_id: str) -> json:
        assert res.status_code == 200
        res_json: json = res.json()
        assert res_json['Name'] == secret_name
        assert res_json['SecretString'] == secret_string
        assert res_json['VersionId'] == version_id
        return res_json

    def secretsmanager_http_get_secret_value_with(self, secret_id: str, version_stage: str) -> requests.Response:
        http_body: json = {
            'SecretId': secret_id,
            'VersionStage': version_stage
        }
        return self.secretsmanager_http_json_post('secretsmanager.GetSecretValue', http_body)

    @staticmethod
    def secretsmanager_http_get_secret_value_with_val_res(
            res: requests.Response, secret_name: str, secret_string: str, version_stage: str) -> json:
        assert res.status_code == 200
        res_json: json = res.json()
        # TODO: is it true that the version id value returned for put requests updating the version stage is equal
        # TODO: to that of the AWSCURRENT version?
        res_json = TestSecretsManager.secretsmanager_http_get_secret_value_val_res(
            res, secret_name, secret_string, res_json['VersionId'])
        assert res_json['VersionStages'] == [version_stage]
        return res_json

    def secretsmanager_http_list_secret_version_ids(self, secret_id: str) -> requests.Response:
        http_body: json = {
            'SecretId': secret_id
        }
        return self.secretsmanager_http_json_post('secretsmanager.ListSecretVersionIds', http_body)

    @staticmethod
    def secretsmanager_http_list_secret_version_ids_val_res(
            res: requests.Response, secret_name: str, versions: json) -> json:
        assert res.status_code == 200
        res_json: json = res.json()
        assert res_json['Name'] == secret_name
        res_versions: [json] = res_json['Versions']
        assert len(res_versions) == len(versions)
        assert len(set([rv['VersionId'] for rv in res_versions])) == len(res_versions)
        assert len(set([v['VersionId'] for v in versions])) == len(versions)
        for version in versions:
            vs_in_res: [json] = list(filter(lambda rv: rv['VersionId'] == version['VersionId'], res_versions))
            assert len(vs_in_res) == 1
            v_in_res = vs_in_res[0]
            assert v_in_res['VersionStages'] == version['VersionStages']
        return res_json

    def secretsmanager_http_put_secret_value(self, secret_id: str, secret_string: str) -> requests.Response:
        http_body: json = {
            'SecretId': secret_id,
            'SecretString': secret_string,
        }
        return self.secretsmanager_http_json_post('secretsmanager.PutSecretValue', http_body)

    @staticmethod
    def secretsmanager_http_put_secret_value_val_res(res: requests.Response, secret_name: str) -> json:
        assert res.status_code == 200
        res_json: json = res.json()
        assert res_json['Name'] == secret_name
        return res_json

    def secretsmanager_http_put_pending_secret_value(self, secret_id: str, secret_string: str) -> requests.Response:
        http_body: json = {
            'SecretId': secret_id,
            'SecretString': secret_string,
            'VersionStages': ['AWSPENDING']
        }
        return self.secretsmanager_http_json_post('secretsmanager.PutSecretValue', http_body)

    @staticmethod
    def secretsmanager_http_put_pending_secret_value_val_res(res: requests.Response, secret_name: str) -> json:
        return TestSecretsManager.secretsmanager_http_put_secret_value_val_res(res, secret_name)

    def secretsmanager_http_put_secret_value_with(
            self, secret_id: str, secret_string: str, client_request_token: Optional[str]) -> requests.Response:
        http_body: json = {
            'SecretId': secret_id,
            'SecretString': secret_string,
            'ClientRequestToken': client_request_token
        }
        return self.secretsmanager_http_json_post('secretsmanager.PutSecretValue', http_body)

    @staticmethod
    def secretsmanager_http_put_secret_value_with_val_res(
            res: requests.Response, secret_name: str, client_request_token: str) -> json:
        assert res.status_code == 200
        res_json: json = res.json()
        assert res_json['Name'] == secret_name
        assert res_json['VersionId'] == client_request_token
        return res_json

    def secretsmanager_http_put_pending_secret_value_with(
            self, secret_id: str, secret_string: str, client_request_token: Optional[str]) -> requests.Response:
        http_body: json = {
            'SecretId': secret_id,
            'SecretString': secret_string,
            'ClientRequestToken': client_request_token,
            'VersionStages': ['AWSPENDING']
        }
        return self.secretsmanager_http_json_post('secretsmanager.PutSecretValue', http_body)

    @staticmethod
    def secretsmanager_http_put_pending_secret_value_with_val_res(
            res: requests.Response, secret_name: str, client_request_token: str) -> json:
        # TODO: is it true that the crt value should be ignored when updating the secrets version stage?
        assert res.status_code == 200
        res_json: json = res.json()
        return TestSecretsManager.secretsmanager_http_put_secret_value_with_val_res(
            res, secret_name, res_json['VersionId'])

    def test_http_put_secret_value_with_new_custom_client_request_token(self):
        secret_name: str = 'test_http_put_secret_value_with_new_custom_client_request_token'

        # Create v0.
        secret_string_v0: str = 'MySecretString'
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0), secret_name)
        #
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json['VersionId'])

        # Update v0 with predefined ClientRequestToken.
        secret_string_v1: str = 'MyNewSecretString'
        #
        crt_v1: str = str(uuid.uuid4())
        while crt_v1 == cr_v0_res_json['VersionId']:
            crt_v1 = str(uuid.uuid4())
        #
        self.secretsmanager_http_put_secret_value_val_res(
            self.secretsmanager_http_put_secret_value_with(secret_name, secret_string_v1, crt_v1), secret_name)
        #
        # Check v1 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v1,
            crt_v1)
        #
        # Check versioning base consistency.
        versions_v0_v1: json = [
            {'VersionId': cr_v0_res_json['VersionId'], 'VersionStages': ['AWSPREVIOUS']},
            {'VersionId': crt_v1, 'VersionStages': ['AWSCURRENT']}
        ]
        self.secretsmanager_http_list_secret_version_ids_val_res(
            self.secretsmanager_http_list_secret_version_ids(secret_name), secret_name, versions_v0_v1)

    def test_http_put_secret_value_with_duplicate_client_request_token(self):
        secret_name: str = 'test_http_put_secret_value_with_duplicate_client_request_token'

        # Create v0.
        secret_string_v0: str = 'MySecretString'
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0), secret_name)
        #
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json['VersionId'])

        # Update v0 with duplicate ClientRequestToken.
        secret_string_v1: str = 'MyNewSecretString'
        #
        crt_v1: str = cr_v0_res_json['VersionId']
        #
        self.secretsmanager_http_put_secret_value_val_res(
            self.secretsmanager_http_put_secret_value_with(secret_name, secret_string_v1, crt_v1), secret_name)
        #
        # Check v1 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v1,
            crt_v1)
        #
        # Check versioning base consistency.
        versions_v0_v1: json = [
            {'VersionId': crt_v1, 'VersionStages': ['AWSCURRENT']}
        ]
        self.secretsmanager_http_list_secret_version_ids_val_res(
            self.secretsmanager_http_list_secret_version_ids(secret_name), secret_name, versions_v0_v1)

    def test_http_put_secret_value_with_null_client_request_token(self):
        secret_name: str = 'test_http_put_secret_value_with_null_client_request_token'

        # Create v0.
        secret_string_v0: str = 'MySecretString'
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0), secret_name)
        #
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json['VersionId'])

        # Update v0 with null ClientRequestToken.
        secret_string_v1: str = 'MyNewSecretString'
        #
        pv_v1_res_json = self.secretsmanager_http_put_secret_value_val_res(
            self.secretsmanager_http_put_secret_value_with(secret_name, secret_string_v1, None), secret_name)
        #
        # Check v1 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v1,
            pv_v1_res_json['VersionId'])
        #
        # Check versioning base consistency.
        versions_v0_v1: json = [
            {'VersionId': cr_v0_res_json['VersionId'], 'VersionStages': ['AWSPREVIOUS']},
            {'VersionId': pv_v1_res_json['VersionId'], 'VersionStages': ['AWSCURRENT']}
        ]
        self.secretsmanager_http_list_secret_version_ids_val_res(
            self.secretsmanager_http_list_secret_version_ids(secret_name), secret_name, versions_v0_v1)

    def test_http_put_secret_value_with_undefined_client_request_token(self):
        secret_name: str = 'test_http_put_secret_value_with_undefined_client_request_token'

        # Create v0.
        secret_string_v0: str = 'MySecretString'
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0), secret_name)
        #
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json['VersionId'])

        # Update v0 with undefined ClientRequestToken.
        secret_string_v1: str = 'MyNewSecretString'
        #
        pv_v1_res_json = self.secretsmanager_http_put_secret_value_val_res(
            self.secretsmanager_http_put_secret_value(secret_name, secret_string_v1), secret_name)
        #
        # Check v1 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v1,
            pv_v1_res_json['VersionId'])
        #
        # Check versioning base consistency.
        versions_v0_v1: json = [
            {'VersionId': cr_v0_res_json['VersionId'], 'VersionStages': ['AWSPREVIOUS']},
            {'VersionId': pv_v1_res_json['VersionId'], 'VersionStages': ['AWSCURRENT']}
        ]
        self.secretsmanager_http_list_secret_version_ids_val_res(
            self.secretsmanager_http_list_secret_version_ids(secret_name), secret_name, versions_v0_v1)

    def test_http_put_secret_value_duplicate_req(self):
        secret_name: str = 'test_http_put_secret_value_duplicate_req'

        # Create v0.
        secret_string_v0: str = 'MySecretString'
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0), secret_name)
        #
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json['VersionId'])

        # Duplicate update.
        self.secretsmanager_http_put_secret_value_val_res(
            self.secretsmanager_http_put_secret_value_with(secret_name, secret_string_v0, cr_v0_res_json['VersionId']),
            secret_name)
        #
        # Check v1 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json['VersionId'])
        #
        # Check versioning base consistency.
        versions_v0_v1: json = [
            {'VersionId': cr_v0_res_json['VersionId'], 'VersionStages': ['AWSCURRENT']},
        ]
        self.secretsmanager_http_list_secret_version_ids_val_res(
            self.secretsmanager_http_list_secret_version_ids(secret_name), secret_name, versions_v0_v1)

    def test_http_put_pending_secret_value_undefined_client_request_token(self):
        secret_name: str = 'test_http_put_pending_secret_value_undefined_client_request_token'

        # Create v0.
        secret_string_v0: str = 'MySecretString'
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0), secret_name)
        #
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json['VersionId'])

        # Update v0 with null ClientRequestToken.
        secret_string_v1: str = 'MyNewSecretString'
        #
        self.secretsmanager_http_put_pending_secret_value_val_res(
            self.secretsmanager_http_put_pending_secret_value(secret_name, secret_string_v1), secret_name)
        #
        # Check v1 base consistency.
        gt_v1_res_json = self.secretsmanager_http_get_secret_value_with_val_res(
            self.secretsmanager_http_get_secret_value_with(secret_name, 'AWSPENDING'),
            secret_name,
            secret_string_v1,
            'AWSPENDING')
        #
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json['VersionId'])
        #
        # Check versioning base consistency.
        versions_v0_v1: json = [
            {'VersionId': cr_v0_res_json['VersionId'], 'VersionStages': ['AWSCURRENT']},
            {'VersionId': gt_v1_res_json['VersionId'], 'VersionStages': ['AWSPENDING']}
        ]
        self.secretsmanager_http_list_secret_version_ids_val_res(
            self.secretsmanager_http_list_secret_version_ids(secret_name), secret_name, versions_v0_v1)

    def test_http_put_pending_secret_value_null_client_request_token(self):
        secret_name: str = 'test_http_put_pending_secret_value_null_client_request_token'

        # Create v0.
        secret_string_v0: str = 'MySecretString'
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0), secret_name)
        #
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json['VersionId'])

        # Update v0 with null ClientRequestToken.
        secret_string_v1: str = 'MyNewSecretString'
        #
        self.secretsmanager_http_put_secret_value_val_res(
            self.secretsmanager_http_put_pending_secret_value_with(secret_name, secret_string_v1, None), secret_name)
        #
        # Check v1 base consistency.
        gt_v1_res_json = self.secretsmanager_http_get_secret_value_with_val_res(
            self.secretsmanager_http_get_secret_value_with(secret_name, 'AWSPENDING'),
            secret_name,
            secret_string_v1,
            'AWSPENDING')
        #
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json['VersionId'])
        #
        # Check versioning base consistency.
        versions_v0_v1: json = [
            {'VersionId': cr_v0_res_json['VersionId'], 'VersionStages': ['AWSCURRENT']},
            {'VersionId': gt_v1_res_json['VersionId'], 'VersionStages': ['AWSPENDING']}
        ]
        self.secretsmanager_http_list_secret_version_ids_val_res(
            self.secretsmanager_http_list_secret_version_ids(secret_name), secret_name, versions_v0_v1)

    def test_http_put_pending_secret_value_custom_client_request_token(self):
        secret_name: str = 'test_http_put_pending_secret_value_custom_client_request_token'

        # Create v0.
        secret_string_v0: str = 'MySecretString'
        cr_v0_res_json: json = self.secretsmanager_http_create_secret_string_val_res(
            self.secretsmanager_http_create_secret_string(secret_name, secret_string_v0), secret_name)
        #
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json['VersionId'])

        # Update v0 with null ClientRequestToken.
        secret_string_v1: str = 'MyNewSecretString'
        #
        crt_v1: str = str(uuid.uuid4())
        while crt_v1 == cr_v0_res_json['VersionId']:
            crt_v1 = str(uuid.uuid4())
        #
        self.secretsmanager_http_put_pending_secret_value_with_val_res(
            self.secretsmanager_http_put_pending_secret_value_with(secret_name, secret_string_v1, crt_v1),
            secret_name,
            crt_v1)
        #
        # Check v1 base consistency.
        gt_v1_res_json = self.secretsmanager_http_get_secret_value_with_val_res(
            self.secretsmanager_http_get_secret_value_with(secret_name, 'AWSPENDING'),
            secret_name,
            secret_string_v1,
            'AWSPENDING')
        #
        assert gt_v1_res_json['VersionId'] == crt_v1
        #
        # Check v0 base consistency.
        self.secretsmanager_http_get_secret_value_val_res(
            self.secretsmanager_http_get_secret_value(secret_name),
            secret_name,
            secret_string_v0,
            cr_v0_res_json['VersionId'])
        #
        # Check versioning base consistency.
        versions_v0_v1: json = [
            {'VersionId': cr_v0_res_json['VersionId'], 'VersionStages': ['AWSCURRENT']},
            {'VersionId': crt_v1, 'VersionStages': ['AWSPENDING']}
        ]
        self.secretsmanager_http_list_secret_version_ids_val_res(
            self.secretsmanager_http_list_secret_version_ids(secret_name), secret_name, versions_v0_v1)
