import os
import re
import threading
import unittest

import pytest
from packaging import version

from localstack.utils.aws import aws_stack
from localstack.utils.common import is_command_available, rm_rf, run, start_worker_thread

BUCKET_NAME = "tf-bucket"
QUEUE_NAME = "tf-queue"
QUEUE_ARN = "arn:aws:sqs:us-east-1:000000000000:tf-queue"

# lambda Testing Variables
LAMBDA_NAME = "tf-lambda"
LAMBDA_ARN = f"arn:aws:lambda:us-east-1:000000000000:function:{LAMBDA_NAME}"
LAMBDA_HANDLER = "DotNetCore2::DotNetCore2.Lambda.Function::SimpleFunctionHandler"
LAMBDA_RUNTIME = "dotnetcore2.0"
LAMBDA_ROLE = "arn:aws:iam::000000000000:role/iam_for_lambda"

INIT_LOCK = threading.RLock()


def check_terraform_version():
    if not is_command_available("terraform"):
        return False, None

    ver_string = run("terraform -version")
    ver_string = re.search(r"v(\d+\.\d+\.\d+)", ver_string).group(1)
    if ver_string is None:
        return False, None
    return version.parse(ver_string) < version.parse("0.15"), ver_string


class TestTerraform(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        available, version = check_terraform_version()

        if not available:
            msg = "could not find a compatible version of terraform"
            if version:
                msg += f" (version = {version})"
            else:
                msg += " (command not found)"

            return pytest.skip(msg)

        with INIT_LOCK:
            run("cd %s; terraform apply -input=false tfplan" % (cls.get_base_dir()))

    @classmethod
    def tearDownClass(cls):
        run("cd %s; terraform destroy -auto-approve" % (cls.get_base_dir()))

    @classmethod
    def init_async(cls):
        available, ver_string = check_terraform_version()
        if not available:
            print(
                "Skipping Terraform test init as version check failed (version: '%s')" % ver_string
            )
            return

        def _run(*args):
            with INIT_LOCK:
                base_dir = cls.get_base_dir()
                if not os.path.exists(os.path.join(base_dir, ".terraform", "plugins")):
                    run("cd %s; terraform init -input=false" % base_dir)
                # remove any cache files from previous runs
                for tf_file in [
                    "tfplan",
                    "terraform.tfstate",
                    "terraform.tfstate.backup",
                ]:
                    rm_rf(os.path.join(base_dir, tf_file))
                # create TF plan
                run("cd %s; terraform plan -out=tfplan -input=false" % base_dir)

        start_worker_thread(_run)

    @classmethod
    def get_base_dir(*args):
        return os.path.join(os.path.dirname(__file__), "terraform")

    def test_bucket_exists(self):
        s3_client = aws_stack.connect_to_service("s3")

        response = s3_client.head_bucket(Bucket=BUCKET_NAME)
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

        cors = {
            "AllowedHeaders": ["*"],
            "AllowedMethods": ["GET", "PUT", "POST"],
            "AllowedOrigins": ["*"],
            "ExposeHeaders": ["ETag", "x-amz-version-id"],
            "MaxAgeSeconds": 3000,
        }

        response = s3_client.get_bucket_cors(Bucket=BUCKET_NAME)
        self.assertEqual(cors, response["CORSRules"][0])

        response = s3_client.get_bucket_versioning(Bucket=BUCKET_NAME)
        self.assertEqual("Enabled", response["Status"])

    def test_sqs(self):
        sqs_client = aws_stack.connect_to_service("sqs")
        queue_url = sqs_client.get_queue_url(QueueName=QUEUE_NAME)["QueueUrl"]
        response = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])

        self.assertEqual("90", response["Attributes"]["DelaySeconds"])
        self.assertEqual("2048", response["Attributes"]["MaximumMessageSize"])
        self.assertEqual("86400", response["Attributes"]["MessageRetentionPeriod"])
        self.assertEqual("10", response["Attributes"]["ReceiveMessageWaitTimeSeconds"])

    def test_lambda(self):
        lambda_client = aws_stack.connect_to_service("lambda")
        response = lambda_client.get_function(FunctionName=LAMBDA_NAME)
        self.assertEqual(LAMBDA_NAME, response["Configuration"]["FunctionName"])
        self.assertEqual(LAMBDA_HANDLER, response["Configuration"]["Handler"])
        self.assertEqual(LAMBDA_RUNTIME, response["Configuration"]["Runtime"])
        self.assertEqual(LAMBDA_ROLE, response["Configuration"]["Role"])

    def test_event_source_mapping(self):
        lambda_client = aws_stack.connect_to_service("lambda")
        all_mappings = lambda_client.list_event_source_mappings(
            EventSourceArn=QUEUE_ARN, FunctionName=LAMBDA_NAME
        )
        function_mapping = all_mappings.get("EventSourceMappings")[0]
        assert function_mapping["FunctionArn"] == LAMBDA_ARN
        assert function_mapping["EventSourceArn"] == QUEUE_ARN

    def test_apigateway(self):
        apigateway_client = aws_stack.connect_to_service("apigateway")
        rest_apis = apigateway_client.get_rest_apis()

        rest_id = None
        for rest_api in rest_apis["items"]:
            if rest_api["name"] == "test-tf-apigateway":
                rest_id = rest_api["id"]
                break

        self.assertTrue(rest_id)
        resources = apigateway_client.get_resources(restApiId=rest_id)["items"]

        # We always have 1 default root resource (with path "/")
        self.assertEqual(3, len(resources))

        res1 = [r for r in resources if r.get("pathPart") == "mytestresource"]
        self.assertTrue(res1)
        self.assertEqual("/mytestresource", res1[0]["path"])
        self.assertEqual(2, len(res1[0]["resourceMethods"]))
        self.assertEqual("MOCK", res1[0]["resourceMethods"]["GET"]["methodIntegration"]["type"])

        res2 = [r for r in resources if r.get("pathPart") == "mytestresource1"]
        self.assertTrue(res2)
        self.assertEqual("/mytestresource1", res2[0]["path"])
        self.assertEqual(2, len(res2[0]["resourceMethods"]))
        self.assertEqual(
            "AWS_PROXY", res2[0]["resourceMethods"]["GET"]["methodIntegration"]["type"]
        )
        self.assertTrue(res2[0]["resourceMethods"]["GET"]["methodIntegration"]["uri"])

    def test_route53(self):
        route53 = aws_stack.connect_to_service("route53")

        response = route53.create_hosted_zone(Name="zone123", CallerReference="ref123")
        self.assertEqual(201, response["ResponseMetadata"]["HTTPStatusCode"])
        change_id = response.get("ChangeInfo", {}).get("Id", "change123")

        response = route53.get_change(Id=change_id)
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

    def test_acm(self):
        acm = aws_stack.connect_to_service("acm")

        certs = acm.list_certificates()["CertificateSummaryList"]
        certs = [c for c in certs if c.get("DomainName") == "example.com"]
        self.assertEqual(1, len(certs))

    def test_apigateway_escaped_policy(self):
        apigateway_client = aws_stack.connect_to_service("apigateway")
        rest_apis = apigateway_client.get_rest_apis()

        service_apis = []

        for rest_api in rest_apis["items"]:
            if rest_api["name"] == "service_api":
                service_apis.append(rest_api)

        self.assertEqual(1, len(service_apis))
