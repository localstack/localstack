import os
import re
import threading

import pytest

from localstack.packages.terraform import terraform_package
from localstack.testing.config import (
    TEST_AWS_ACCESS_KEY_ID,
    TEST_AWS_REGION_NAME,
    TEST_AWS_SECRET_ACCESS_KEY,
)
from localstack.testing.pytest import markers
from localstack.utils.common import is_command_available, rm_rf, run, start_worker_thread

#  TODO: remove all of these

BUCKET_NAME = "tf-bucket"
QUEUE_NAME = "tf-queue"
QUEUE_ARN = "arn:aws:sqs:us-east-1:{account_id}:tf-queue"

# lambda Testing Variables
LAMBDA_NAME = "tf-lambda"
LAMBDA_ARN = "arn:aws:lambda:us-east-1:{account_id}:function:{lambda_name}"
LAMBDA_HANDLER = "index.handler"
LAMBDA_RUNTIME = "python3.8"
LAMBDA_ROLE = "arn:aws:iam::{account_id}:role/iam_for_lambda"

INIT_LOCK = threading.RLock()

# set after calling install()
TERRAFORM_BIN = None


def check_terraform_version():
    if not is_command_available(TERRAFORM_BIN):
        return False, None

    ver_string = run([TERRAFORM_BIN, "-version"])
    ver_string = re.search(r"v(\d+\.\d+\.\d+)", ver_string).group(1)
    if ver_string is None:
        return False, None
    return True, ver_string


@pytest.fixture(scope="module", autouse=True)
def setup_test(account_id, region_name):
    with INIT_LOCK:
        available, version = check_terraform_version()

        if not available:
            msg = "could not find a compatible version of terraform"
            if version:
                msg += f" (version = {version})"
            else:
                msg += " (command not found)"

            return pytest.skip(msg)

        env_vars = {
            "AWS_ACCESS_KEY_ID": account_id,
            "AWS_SECRET_ACCESS_KEY": account_id,
            "AWS_REGION": region_name,
        }

        run(
            "cd %s; %s apply -input=false tfplan" % (get_base_dir(), TERRAFORM_BIN),
            env_vars=env_vars,
        )

    yield

    # clean up
    run("cd %s; %s destroy -auto-approve" % (get_base_dir(), TERRAFORM_BIN), env_vars=env_vars)


def get_base_dir():
    return os.path.join(os.path.dirname(__file__), "terraform")


# TODO: replace "clouddrove/api-gateway/aws" with normal apigateway module and update terraform
# TODO: rework this setup for multiple (potentially parallel) terraform tests by providing variables (see .auto.tfvars)
# TODO: fetch generated ARNs from terraform instead of static/building ARNs
@pytest.mark.skip(reason="disabled until further notice due to flakiness and lacking quality")
class TestTerraform:
    @classmethod
    def init_async(cls):
        def _run(*args):
            with INIT_LOCK:
                terraform_package.install()
                global TERRAFORM_BIN
                TERRAFORM_BIN = terraform_package.get_installer().get_executable_path()
                base_dir = get_base_dir()
                env_vars = {
                    "AWS_ACCESS_KEY_ID": TEST_AWS_ACCESS_KEY_ID,
                    "AWS_SECRET_ACCESS_KEY": TEST_AWS_SECRET_ACCESS_KEY,
                    "AWS_REGION": TEST_AWS_REGION_NAME,
                }
                if not os.path.exists(os.path.join(base_dir, ".terraform", "plugins")):
                    run(f"cd {base_dir}; {TERRAFORM_BIN} init -input=false", env_vars=env_vars)
                # remove any cache files from previous runs
                for tf_file in [
                    "tfplan",
                    "terraform.tfstate",
                    "terraform.tfstate.backup",
                ]:
                    rm_rf(os.path.join(base_dir, tf_file))
                # create TF plan
                run(
                    f"cd {base_dir}; {TERRAFORM_BIN} plan -out=tfplan -input=false",
                    env_vars=env_vars,
                )

        start_worker_thread(_run)

    @markers.skip_offline
    @markers.aws.needs_fixing
    def test_bucket_exists(self, aws_client):
        response = aws_client.s3.head_bucket(Bucket=BUCKET_NAME)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        cors = {
            "AllowedHeaders": ["*"],
            "AllowedMethods": ["GET", "PUT", "POST"],
            "AllowedOrigins": ["*"],
            "ExposeHeaders": ["ETag", "x-amz-version-id"],
            "MaxAgeSeconds": 3000,
        }

        response = aws_client.s3.get_bucket_cors(Bucket=BUCKET_NAME)
        assert response["CORSRules"][0] == cors

        response = aws_client.s3.get_bucket_versioning(Bucket=BUCKET_NAME)
        assert response["Status"] == "Enabled"

    @markers.skip_offline
    @markers.aws.needs_fixing
    def test_sqs(self, aws_client):
        queue_url = aws_client.sqs.get_queue_url(QueueName=QUEUE_NAME)["QueueUrl"]
        response = aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])

        assert response["Attributes"]["DelaySeconds"] == "90"
        assert response["Attributes"]["MaximumMessageSize"] == "2048"
        assert response["Attributes"]["MessageRetentionPeriod"] == "86400"
        assert response["Attributes"]["ReceiveMessageWaitTimeSeconds"] == "10"

    @markers.skip_offline
    @markers.aws.needs_fixing
    def test_lambda(self, aws_client, account_id):
        response = aws_client.lambda_.get_function(FunctionName=LAMBDA_NAME)
        assert response["Configuration"]["FunctionName"] == LAMBDA_NAME
        assert response["Configuration"]["Handler"] == LAMBDA_HANDLER
        assert response["Configuration"]["Runtime"] == LAMBDA_RUNTIME
        assert response["Configuration"]["Role"] == LAMBDA_ROLE.format(account_id=account_id)

    @markers.skip_offline
    @markers.aws.needs_fixing
    def test_event_source_mapping(self, aws_client, account_id):
        queue_arn = QUEUE_ARN.format(account_id=account_id)
        lambda_arn = LAMBDA_ARN.format(account_id=account_id, lambda_name=LAMBDA_NAME)
        all_mappings = aws_client.lambda_.list_event_source_mappings(
            EventSourceArn=queue_arn, FunctionName=LAMBDA_NAME
        )
        function_mapping = all_mappings.get("EventSourceMappings")[0]
        assert function_mapping["FunctionArn"] == lambda_arn
        assert function_mapping["EventSourceArn"] == queue_arn

    @markers.skip_offline
    @pytest.mark.skip(reason="flaky")
    @markers.aws.needs_fixing
    def test_apigateway(self, aws_client):
        rest_apis = aws_client.apigateway.get_rest_apis()

        rest_id = None
        for rest_api in rest_apis["items"]:
            if rest_api["name"] == "test-tf-apigateway":
                rest_id = rest_api["id"]
                break

        assert rest_id
        resources = aws_client.apigateway.get_resources(restApiId=rest_id)["items"]

        # We always have 1 default root resource (with path "/")
        assert len(resources) == 3

        res1 = [r for r in resources if r.get("pathPart") == "mytestresource"]
        assert res1
        assert res1[0]["path"] == "/mytestresource"
        assert len(res1[0]["resourceMethods"]) == 2
        assert res1[0]["resourceMethods"]["GET"]["methodIntegration"]["type"] == "MOCK"

        res2 = [r for r in resources if r.get("pathPart") == "mytestresource1"]
        assert res2
        assert res2[0]["path"] == "/mytestresource1"
        assert len(res2[0]["resourceMethods"]) == 2
        assert res2[0]["resourceMethods"]["GET"]["methodIntegration"]["type"] == "AWS_PROXY"
        assert res2[0]["resourceMethods"]["GET"]["methodIntegration"]["uri"]

    @markers.skip_offline
    @markers.aws.needs_fixing
    def test_route53(self, aws_client):
        response = aws_client.route53.create_hosted_zone(Name="zone123", CallerReference="ref123")
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 201
        change_id = response.get("ChangeInfo", {}).get("Id", "change123")

        response = aws_client.route53.get_change(Id=change_id)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    @markers.skip_offline
    @markers.aws.needs_fixing
    def test_acm(self, aws_client):
        certs = aws_client.acm.list_certificates()["CertificateSummaryList"]
        certs = [c for c in certs if c.get("DomainName") == "example.com"]
        assert len(certs) == 1

    @markers.skip_offline
    @pytest.mark.skip(reason="flaky")
    @markers.aws.needs_fixing
    def test_apigateway_escaped_policy(self, aws_client):
        rest_apis = aws_client.apigateway.get_rest_apis()

        service_apis = []

        for rest_api in rest_apis["items"]:
            if rest_api["name"] == "service_api":
                service_apis.append(rest_api)

        assert len(service_apis) == 1

    @markers.skip_offline
    @markers.aws.needs_fixing
    def test_dynamodb(self, aws_client):
        def _table_exists(tablename, dynamotables):
            return any(name for name in dynamotables["TableNames"] if name == tablename)

        tables = aws_client.dynamodb.list_tables()
        assert _table_exists("tf_dynamotable1", tables)
        assert _table_exists("tf_dynamotable2", tables)
        assert _table_exists("tf_dynamotable3", tables)

    @markers.skip_offline
    @markers.aws.needs_fixing
    def test_security_groups(self, aws_client):
        rules = aws_client.ec2.describe_security_groups(MaxResults=100)["SecurityGroups"]
        matching = [r for r in rules if r["Description"] == "TF SG with ingress / egress rules"]
        assert matching
