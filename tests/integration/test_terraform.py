import os
import re
import threading

import pytest

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.packages.terraform import terraform_package
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
def setup_test():
    with INIT_LOCK:
        if config.DEFAULT_REGION != "us-east-1":
            pytest.skip("Currently only support us-east-1")
        available, version = check_terraform_version()

        if not available:
            msg = "could not find a compatible version of terraform"
            if version:
                msg += f" (version = {version})"
            else:
                msg += " (command not found)"

            return pytest.skip(msg)

        run("cd %s; %s apply -input=false tfplan" % (get_base_dir(), TERRAFORM_BIN))

    yield

    # clean up
    run("cd %s; %s destroy -auto-approve" % (get_base_dir(), TERRAFORM_BIN))


def get_base_dir():
    return os.path.join(os.path.dirname(__file__), "terraform")


# TODO: replace "clouddrove/api-gateway/aws" with normal apigateway module and update terraform
# TODO: rework this setup for multiple (potentially parallel) terraform tests by providing variables (see .auto.tfvars)
# TODO: fetch generated ARNs from terraform instead of static/building ARNs
class TestTerraform:
    @classmethod
    def init_async(cls):
        def _run(*args):
            with INIT_LOCK:
                terraform_package.install()
                global TERRAFORM_BIN
                TERRAFORM_BIN = terraform_package.get_installer().get_executable_path()
                base_dir = get_base_dir()
                if not os.path.exists(os.path.join(base_dir, ".terraform", "plugins")):
                    run(f"cd {base_dir}; {TERRAFORM_BIN} init -input=false")
                # remove any cache files from previous runs
                for tf_file in [
                    "tfplan",
                    "terraform.tfstate",
                    "terraform.tfstate.backup",
                ]:
                    rm_rf(os.path.join(base_dir, tf_file))
                # create TF plan
                run(f"cd {base_dir}; {TERRAFORM_BIN} plan -out=tfplan -input=false")

        start_worker_thread(_run)

    @pytest.mark.skip_offline
    def test_bucket_exists(self, s3_client):
        response = s3_client.head_bucket(Bucket=BUCKET_NAME)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        cors = {
            "AllowedHeaders": ["*"],
            "AllowedMethods": ["GET", "PUT", "POST"],
            "AllowedOrigins": ["*"],
            "ExposeHeaders": ["ETag", "x-amz-version-id"],
            "MaxAgeSeconds": 3000,
        }

        response = s3_client.get_bucket_cors(Bucket=BUCKET_NAME)
        assert response["CORSRules"][0] == cors

        response = s3_client.get_bucket_versioning(Bucket=BUCKET_NAME)
        assert response["Status"] == "Enabled"

    @pytest.mark.skip_offline
    def test_sqs(self, sqs_client):
        queue_url = sqs_client.get_queue_url(QueueName=QUEUE_NAME)["QueueUrl"]
        response = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])

        assert response["Attributes"]["DelaySeconds"] == "90"
        assert response["Attributes"]["MaximumMessageSize"] == "2048"
        assert response["Attributes"]["MessageRetentionPeriod"] == "86400"
        assert response["Attributes"]["ReceiveMessageWaitTimeSeconds"] == "10"

    @pytest.mark.skip_offline
    def test_lambda(self, lambda_client):
        account_id = get_aws_account_id()
        response = lambda_client.get_function(FunctionName=LAMBDA_NAME)
        assert response["Configuration"]["FunctionName"] == LAMBDA_NAME
        assert response["Configuration"]["Handler"] == LAMBDA_HANDLER
        assert response["Configuration"]["Runtime"] == LAMBDA_RUNTIME
        assert response["Configuration"]["Role"] == LAMBDA_ROLE.format(account_id=account_id)

    @pytest.mark.skip_offline
    def test_event_source_mapping(self, lambda_client):
        queue_arn = QUEUE_ARN.format(account_id=get_aws_account_id())
        lambda_arn = LAMBDA_ARN.format(account_id=get_aws_account_id(), lambda_name=LAMBDA_NAME)
        all_mappings = lambda_client.list_event_source_mappings(
            EventSourceArn=queue_arn, FunctionName=LAMBDA_NAME
        )
        function_mapping = all_mappings.get("EventSourceMappings")[0]
        assert function_mapping["FunctionArn"] == lambda_arn
        assert function_mapping["EventSourceArn"] == queue_arn

    @pytest.mark.skip_offline
    @pytest.mark.xfail(reason="flaky")
    def test_apigateway(self, apigateway_client):
        rest_apis = apigateway_client.get_rest_apis()

        rest_id = None
        for rest_api in rest_apis["items"]:
            if rest_api["name"] == "test-tf-apigateway":
                rest_id = rest_api["id"]
                break

        assert rest_id
        resources = apigateway_client.get_resources(restApiId=rest_id)["items"]

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

    @pytest.mark.skip_offline
    def test_route53(self, route53_client):
        response = route53_client.create_hosted_zone(Name="zone123", CallerReference="ref123")
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 201
        change_id = response.get("ChangeInfo", {}).get("Id", "change123")

        response = route53_client.get_change(Id=change_id)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    @pytest.mark.skip_offline
    def test_acm(self, acm_client):
        certs = acm_client.list_certificates()["CertificateSummaryList"]
        certs = [c for c in certs if c.get("DomainName") == "example.com"]
        assert len(certs) == 1

    @pytest.mark.skip_offline
    @pytest.mark.xfail(reason="flaky")
    def test_apigateway_escaped_policy(self, apigateway_client):
        rest_apis = apigateway_client.get_rest_apis()

        service_apis = []

        for rest_api in rest_apis["items"]:
            if rest_api["name"] == "service_api":
                service_apis.append(rest_api)

        assert len(service_apis) == 1

    @pytest.mark.skip_offline
    def test_dynamodb(self, dynamodb_client):
        def _table_exists(tablename, dynamotables):
            return any(name for name in dynamotables["TableNames"] if name == tablename)

        tables = dynamodb_client.list_tables()
        assert _table_exists("tf_dynamotable1", tables)
        assert _table_exists("tf_dynamotable2", tables)
        assert _table_exists("tf_dynamotable3", tables)

    @pytest.mark.skip_offline
    def test_security_groups(self, ec2_client):
        rules = ec2_client.describe_security_groups(MaxResults=100)["SecurityGroups"]
        matching = [r for r in rules if r["Description"] == "TF SG with ingress / egress rules"]
        assert matching
