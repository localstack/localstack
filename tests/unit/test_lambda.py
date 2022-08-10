import datetime
import json
import os
import re
import time
import unittest
from unittest import mock

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.services.awslambda import lambda_api, lambda_executors, lambda_utils
from localstack.services.awslambda.lambda_api import get_lambda_policy_name
from localstack.services.awslambda.lambda_executors import OutputLog, Util
from localstack.services.awslambda.lambda_utils import API_PATH_ROOT
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_models import LambdaFunction
from localstack.utils.common import isoformat_milliseconds, mkdir, new_tmp_dir, save_file
from localstack.utils.container_utils.container_client import VolumeInfo

TEST_EVENT_SOURCE_ARN = "arn:aws:sqs:eu-west-1:000000000000:testq"
TEST_SECRETSMANANAGER_EVENT_SOURCE_ARN = (
    "arn:aws:secretsmanager:us-east-1:000000000000:secret:mysecret-kUBhE"
)


class TestLambdaAPI(unittest.TestCase):
    CODE_SIZE = 50
    CODE_SHA_256 = "/u60ZpAA9bzZPVwb8d4390i5oqP1YAObUwV03CZvsWA="
    UPDATED_CODE_SHA_256 = "/u6A="
    MEMORY_SIZE = 128
    ROLE = "arn:aws:iam::123456:role/role-name"
    LAST_MODIFIED = datetime.datetime.utcnow()
    TRACING_CONFIG = {"Mode": "PassThrough"}
    REVISION_ID = "e54dbcf8-e3ef-44ab-9af7-8dbef510608a"
    HANDLER = "index.handler"
    RUNTIME = "node.js4.3"
    TIMEOUT = 60  # Default value, hardcoded
    FUNCTION_NAME = "test1"
    ALIAS_NAME = "alias1"
    ALIAS2_NAME = "alias2"
    RESOURCENOTFOUND_EXCEPTION = "ResourceNotFoundException"
    RESOURCENOTFOUND_MESSAGE = "Function not found: %s"
    ALIASEXISTS_EXCEPTION = "ResourceConflictException"
    ALIASEXISTS_MESSAGE = "Alias already exists: %s"
    ALIASNOTFOUND_EXCEPTION = "ResourceNotFoundException"
    ALIASNOTFOUND_MESSAGE = "Alias not found: %s"
    TEST_UUID = "Test"
    TAGS = {"hello": "world", "env": "prod"}

    def setUp(self):
        lambda_api.cleanup()
        self.maxDiff = None
        self.app = lambda_api.app
        self.app.testing = True
        self.client = self.app.test_client()

    def test_get_non_existent_function_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(lambda_api.get_function("non_existent_function_name").get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result["__type"])
            self.assertEqual(
                self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn("non_existent_function_name"),
                result["message"],
            )

    def test_get_function_single_function_returns_correect_function(self):
        with self.app.test_request_context():
            self._create_function("myFunction")
            result = json.loads(lambda_api.get_function("myFunction").get_data())
            self.assertEqual(
                result["Configuration"]["FunctionArn"],
                aws_stack.lambda_function_arn("myFunction"),
            )

    def test_get_function_two_functions_with_similar_names_match_by_name(self):
        with self.app.test_request_context():
            self._create_function("myFunctions")
            self._create_function("myFunction")
            result = json.loads(lambda_api.get_function("myFunction").get_data())
            self.assertEqual(
                result["Configuration"]["FunctionArn"],
                aws_stack.lambda_function_arn("myFunction"),
            )
            result = json.loads(lambda_api.get_function("myFunctions").get_data())
            self.assertEqual(
                result["Configuration"]["FunctionArn"], aws_stack.lambda_function_arn("myFunctions")
            )

    def test_get_function_two_functions_with_similar_names_match_by_arn(self):
        with self.app.test_request_context():
            self._create_function("myFunctions")
            self._create_function("myFunction")
            result = json.loads(
                lambda_api.get_function(aws_stack.lambda_function_arn("myFunction")).get_data()
            )
            self.assertEqual(
                result["Configuration"]["FunctionArn"], aws_stack.lambda_function_arn("myFunction")
            )
            result = json.loads(
                lambda_api.get_function(aws_stack.lambda_function_arn("myFunctions")).get_data()
            )
            self.assertEqual(
                result["Configuration"]["FunctionArn"], aws_stack.lambda_function_arn("myFunctions")
            )

    def test_get_function_two_functions_with_similar_names_match_by_partial_arn(self):
        with self.app.test_request_context():
            self._create_function("myFunctions")
            self._create_function("myFunction")
            result = json.loads(
                lambda_api.get_function(
                    f"{aws_stack.get_region()}:000000000000:function:myFunction"
                ).get_data()
            )
            self.assertEqual(
                result["Configuration"]["FunctionArn"], aws_stack.lambda_function_arn("myFunction")
            )
            result = json.loads(
                lambda_api.get_function(
                    f"{aws_stack.get_region()}:000000000000:function:myFunctions"
                ).get_data()
            )
            self.assertEqual(
                result["Configuration"]["FunctionArn"], aws_stack.lambda_function_arn("myFunctions")
            )

    def test_get_event_source_mapping(self):
        region = lambda_api.LambdaRegion.get()
        with self.app.test_request_context():
            region.event_source_mappings.append({"UUID": self.TEST_UUID})
            result = lambda_api.get_event_source_mapping(self.TEST_UUID)
            self.assertEqual(self.TEST_UUID, json.loads(result.get_data()).get("UUID"))

    def test_get_event_sources(self):
        region = lambda_api.LambdaRegion.get()
        with self.app.test_request_context():
            region.event_source_mappings.append(
                {"UUID": self.TEST_UUID, "EventSourceArn": "the_arn"}
            )

            # Match source ARN
            result = lambda_api.get_event_sources(source_arn="the_arn")
            self.assertEqual(1, len(result))
            self.assertEqual(self.TEST_UUID, result[0].get("UUID"))

            # No partial match on source ARN
            result = lambda_api.get_event_sources(source_arn="the_")
            self.assertEqual(0, len(result))

    def test_get_event_sources_with_paths(self):
        region = lambda_api.LambdaRegion.get()
        with self.app.test_request_context():
            region.event_source_mappings.append(
                {"UUID": self.TEST_UUID, "EventSourceArn": "the_arn/path/subpath"}
            )

            # Do partial match on paths
            result = lambda_api.get_event_sources(source_arn="the_arn")
            self.assertEqual(1, len(result))
            result = lambda_api.get_event_sources(source_arn="the_arn/path")
            self.assertEqual(1, len(result))

    def test_delete_event_source_mapping(self):
        region = lambda_api.LambdaRegion.get()
        with self.app.test_request_context():
            region.event_source_mappings.append({"UUID": self.TEST_UUID})
            result = lambda_api.delete_event_source_mapping(self.TEST_UUID)
            self.assertEqual(self.TEST_UUID, json.loads(result.get_data()).get("UUID"))
            self.assertEqual(0, len(region.event_source_mappings))

    def test_invoke_RETURNS_415_WHEN_not_json_input(self):
        with self.app.test_request_context() as context:
            context.request._cached_data = "~notjsonrequest~"
            response = lambda_api.invoke_function(self.FUNCTION_NAME)
            self.assertEqual("415 UNSUPPORTED MEDIA TYPE", response.status)

    def _request_response(self, context):
        context.request._cached_data = "{}"
        context.request.args = {"Qualifier": "$LATEST"}
        context.request.environ["HTTP_X_AMZ_INVOCATION_TYPE"] = "RequestResponse"
        self._create_function(self.FUNCTION_NAME)

    @mock.patch("localstack.services.awslambda.lambda_api.run_lambda")
    def test_invoke_plain_text_response(self, mock_run_lambda):
        with self.app.test_request_context() as context:
            self._request_response(context)
            mock_run_lambda.return_value = "~notjsonresponse~"
            response = lambda_api.invoke_function(self.FUNCTION_NAME)
            self.assertEqual("~notjsonresponse~", response[0])
            self.assertEqual(200, response[1])

            headers = response[2]
            self.assertEqual("text/plain", headers["Content-Type"])

    @mock.patch("localstack.services.awslambda.lambda_api.run_lambda")
    def test_invoke_empty_plain_text_response(self, mock_run_lambda):
        with self.app.test_request_context() as context:
            self._request_response(context)
            mock_run_lambda.return_value = ""
            response = lambda_api.invoke_function(self.FUNCTION_NAME)
            self.assertEqual("", response[0])
            self.assertEqual(200, response[1])

            headers = response[2]
            self.assertEqual("text/plain", headers["Content-Type"])

    @mock.patch("localstack.services.awslambda.lambda_api.run_lambda")
    def test_invoke_empty_map_json_response(self, mock_run_lambda):
        with self.app.test_request_context() as context:
            self._request_response(context)
            mock_run_lambda.return_value = "{}"
            response = lambda_api.invoke_function(self.FUNCTION_NAME)
            self.assertEqual(b"{}\n", response[0].response[0])
            self.assertEqual(200, response[1])
            self.assertEqual("application/json", response[0].headers["Content-Type"])

    @mock.patch("localstack.services.awslambda.lambda_api.run_lambda")
    def test_invoke_populated_map_json_response(self, mock_run_lambda):
        with self.app.test_request_context() as context:
            self._request_response(context)
            mock_run_lambda.return_value = '{"bool":true,"int":1}'
            response = lambda_api.invoke_function(self.FUNCTION_NAME)
            self.assertEqual(b'{"bool":true,"int":1}\n', response[0].response[0])
            self.assertEqual(200, response[1])
            self._assert_contained({"Content-Type": "application/json"}, response[0].headers)

    @mock.patch("localstack.services.awslambda.lambda_api.run_lambda")
    def test_invoke_empty_list_json_response(self, mock_run_lambda):
        with self.app.test_request_context() as context:
            self._request_response(context)
            mock_run_lambda.return_value = "[]"
            response = lambda_api.invoke_function(self.FUNCTION_NAME)
            self.assertEqual(b"[]\n", response[0].response[0])
            self.assertEqual(200, response[1])
            self._assert_contained({"Content-Type": "application/json"}, response[0].headers)

    @mock.patch("localstack.services.awslambda.lambda_api.run_lambda")
    def test_invoke_populated_list_json_response(self, mock_run_lambda):
        with self.app.test_request_context() as context:
            self._request_response(context)
            mock_run_lambda.return_value = '[true,1,"thing"]'
            response = lambda_api.invoke_function(self.FUNCTION_NAME)
            self.assertEqual(b'[true,1,"thing"]\n', response[0].response[0])
            self.assertEqual(200, response[1])
            self._assert_contained({"Content-Type": "application/json"}, response[0].headers)

    @mock.patch("localstack.services.awslambda.lambda_api.run_lambda")
    def test_invoke_string_json_response(self, mock_run_lambda):
        with self.app.test_request_context() as context:
            self._request_response(context)
            mock_run_lambda.return_value = '"thing"'
            response = lambda_api.invoke_function(self.FUNCTION_NAME)
            self.assertEqual(b'"thing"\n', response[0].response[0])
            self.assertEqual(200, response[1])
            self._assert_contained({"Content-Type": "application/json"}, response[0].headers)

    @mock.patch("localstack.services.awslambda.lambda_api.run_lambda")
    def test_invoke_integer_json_response(self, mock_run_lambda):
        with self.app.test_request_context() as context:
            self._request_response(context)
            mock_run_lambda.return_value = "1234"
            response = lambda_api.invoke_function(self.FUNCTION_NAME)
            self.assertEqual(b"1234\n", response[0].response[0])
            self.assertEqual(200, response[1])
            self._assert_contained({"Content-Type": "application/json"}, response[0].headers)

    @mock.patch("localstack.services.awslambda.lambda_api.run_lambda")
    def test_invoke_float_json_response(self, mock_run_lambda):
        with self.app.test_request_context() as context:
            self._request_response(context)
            mock_run_lambda.return_value = "1.3"
            response = lambda_api.invoke_function(self.FUNCTION_NAME)
            print(f"float - {response[0].headers}")
            self.assertEqual(b"1.3\n", response[0].response[0])
            self.assertEqual(200, response[1])
            self._assert_contained({"Content-Type": "application/json"}, response[0].headers)

    @mock.patch("localstack.services.awslambda.lambda_api.run_lambda")
    def test_invoke_boolean_json_response(self, mock_run_lambda):
        with self.app.test_request_context() as context:
            self._request_response(context)
            mock_run_lambda.return_value = "true"
            response = lambda_api.invoke_function(self.FUNCTION_NAME)
            self.assertEqual(b"true\n", response[0].response[0])
            self.assertEqual(200, response[1])
            self._assert_contained({"Content-Type": "application/json"}, response[0].headers)

    @mock.patch("localstack.services.awslambda.lambda_api.run_lambda")
    def test_invoke_null_json_response(self, mock_run_lambda):
        with self.app.test_request_context() as context:
            self._request_response(context)
            mock_run_lambda.return_value = "null"
            response = lambda_api.invoke_function(self.FUNCTION_NAME)
            self.assertEqual(b"null\n", response[0].response[0])
            self.assertEqual(200, response[1])
            self._assert_contained({"Content-Type": "application/json"}, response[0].headers)

    def test_create_event_source_mapping(self):
        self.client.post(
            "{0}/event-source-mappings/".format(API_PATH_ROOT),
            data=json.dumps(
                {
                    "FunctionName": "test-lambda-function",
                    "EventSourceArn": TEST_EVENT_SOURCE_ARN,
                }
            ),
        )

        listResponse = self.client.get("{0}/event-source-mappings/".format(API_PATH_ROOT))
        listResult = json.loads(listResponse.get_data())

        eventSourceMappings = listResult.get("EventSourceMappings")

        self.assertEqual(1, len(eventSourceMappings))
        self.assertEqual("Enabled", eventSourceMappings[0]["State"])

    def test_create_event_source_mapping_self_managed_event_source(self):
        self.client.post(
            "{0}/event-source-mappings/".format(API_PATH_ROOT),
            data=json.dumps(
                {
                    "FunctionName": "test-lambda-function",
                    "Topics": ["test"],
                    "SourceAccessConfigurations": [
                        {
                            "Type": "SASL_SCRAM_512_AUTH",
                            "URI": TEST_SECRETSMANANAGER_EVENT_SOURCE_ARN,
                        }
                    ],
                    "SelfManagedEventSource": {
                        "Endpoints": {"KAFKA_BOOTSTRAP_SERVERS": ["127.0.0.1:9092"]}
                    },
                }
            ),
        )
        listResponse = self.client.get("{0}/event-source-mappings/".format(API_PATH_ROOT))
        listResult = json.loads(listResponse.get_data())

        eventSourceMappings = listResult.get("EventSourceMappings")

        self.assertEqual(1, len(eventSourceMappings))
        self.assertEqual("Enabled", eventSourceMappings[0]["State"])

    def test_create_disabled_event_source_mapping(self):
        createResponse = self.client.post(
            f"{API_PATH_ROOT}/event-source-mappings/",
            data=json.dumps(
                {
                    "FunctionName": "test-lambda-function",
                    "EventSourceArn": TEST_EVENT_SOURCE_ARN,
                    "Enabled": "false",
                }
            ),
        )
        createResult = json.loads(createResponse.get_data())

        self.assertEqual("Disabled", createResult["State"])

        getResponse = self.client.get(
            "{0}/event-source-mappings/{1}".format(API_PATH_ROOT, createResult.get("UUID"))
        )
        getResult = json.loads(getResponse.get_data())

        self.assertEqual("Disabled", getResult["State"])

    def test_update_event_source_mapping(self):
        createResponse = self.client.post(
            "{0}/event-source-mappings/".format(API_PATH_ROOT),
            data=json.dumps(
                {
                    "FunctionName": "test-lambda-function",
                    "EventSourceArn": TEST_EVENT_SOURCE_ARN,
                    "Enabled": "true",
                }
            ),
        )
        createResult = json.loads(createResponse.get_data())

        putResponse = self.client.put(
            "{0}/event-source-mappings/{1}".format(API_PATH_ROOT, createResult.get("UUID")),
            data=json.dumps({"Enabled": "false"}),
        )
        putResult = json.loads(putResponse.get_data())

        self.assertEqual("Disabled", putResult["State"])

        getResponse = self.client.get(
            "{0}/event-source-mappings/{1}".format(API_PATH_ROOT, createResult.get("UUID"))
        )
        getResult = json.loads(getResponse.get_data())

        self.assertEqual("Disabled", getResult["State"])

    def test_update_event_source_mapping_self_managed_event_source(self):
        createResponse = self.client.post(
            "{0}/event-source-mappings/".format(API_PATH_ROOT),
            data=json.dumps(
                {
                    "FunctionName": "test-lambda-function",
                    "Topics": ["test"],
                    "SourceAccessConfigurations": [
                        {
                            "Type": "SASL_SCRAM_512_AUTH",
                            "URI": TEST_SECRETSMANANAGER_EVENT_SOURCE_ARN,
                        }
                    ],
                    "SelfManagedEventSource": {
                        "Endpoints": {"KAFKA_BOOTSTRAP_SERVERS": ["127.0.0.1:9092"]}
                    },
                    "Enabled": "true",
                }
            ),
        )
        createResult = json.loads(createResponse.get_data())

        putResponse = self.client.put(
            "{0}/event-source-mappings/{1}".format(API_PATH_ROOT, createResult.get("UUID")),
            data=json.dumps({"Enabled": "false"}),
        )
        putResult = json.loads(putResponse.get_data())

        self.assertEqual("Disabled", putResult["State"])

        getResponse = self.client.get(
            "{0}/event-source-mappings/{1}".format(API_PATH_ROOT, createResult.get("UUID"))
        )
        getResult = json.loads(getResponse.get_data())

        self.assertEqual("Disabled", getResult["State"])

    def test_publish_function_version(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)

            result = json.loads(lambda_api.publish_version(self.FUNCTION_NAME).get_data())
            result.pop(
                "RevisionId", None
            )  # we need to remove this, since this is random, so we cannot know its value

            expected_result = {}
            expected_result["CodeSize"] = self.CODE_SIZE
            expected_result["CodeSha256"] = self.CODE_SHA_256
            expected_result["FunctionArn"] = str(lambda_api.func_arn(self.FUNCTION_NAME)) + ":1"
            expected_result["FunctionName"] = str(self.FUNCTION_NAME)
            expected_result["Handler"] = str(self.HANDLER)
            expected_result["Runtime"] = str(self.RUNTIME)
            expected_result["Timeout"] = self.TIMEOUT
            expected_result["Description"] = ""
            expected_result["MemorySize"] = self.MEMORY_SIZE
            expected_result["Role"] = self.ROLE
            expected_result["KMSKeyArn"] = None
            expected_result["VpcConfig"] = None
            expected_result["LastModified"] = isoformat_milliseconds(self.LAST_MODIFIED) + "+0000"
            expected_result["TracingConfig"] = self.TRACING_CONFIG
            expected_result["Version"] = "1"
            expected_result["State"] = "Active"
            expected_result["LastUpdateStatus"] = "Successful"
            expected_result["PackageType"] = None
            expected_result["ImageConfig"] = {}
            expected_result["Architectures"] = ["x86_64"]
            # Check that the result contains the expected fields (some pro extensions could add additional fields)
            self.assertDictContainsSubset(expected_result, result)

    def test_publish_update_version_increment(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)
            lambda_api.publish_version(self.FUNCTION_NAME)

            self._update_function_code(self.FUNCTION_NAME)
            result = json.loads(lambda_api.publish_version(self.FUNCTION_NAME).get_data())
            result.pop(
                "RevisionId", None
            )  # we need to remove this, since this is random, so we cannot know its value

            expected_result = {}
            expected_result["CodeSize"] = self.CODE_SIZE
            expected_result["CodeSha256"] = self.UPDATED_CODE_SHA_256
            expected_result["FunctionArn"] = str(lambda_api.func_arn(self.FUNCTION_NAME)) + ":2"
            expected_result["FunctionName"] = str(self.FUNCTION_NAME)
            expected_result["Handler"] = str(self.HANDLER)
            expected_result["Runtime"] = str(self.RUNTIME)
            expected_result["Timeout"] = self.TIMEOUT
            expected_result["Description"] = ""
            expected_result["MemorySize"] = self.MEMORY_SIZE
            expected_result["Role"] = self.ROLE
            expected_result["KMSKeyArn"] = None
            expected_result["VpcConfig"] = None
            expected_result["LastModified"] = isoformat_milliseconds(self.LAST_MODIFIED) + "+0000"
            expected_result["TracingConfig"] = self.TRACING_CONFIG
            expected_result["Version"] = "2"
            expected_result["State"] = "Active"
            expected_result["LastUpdateStatus"] = "Successful"
            expected_result["PackageType"] = None
            expected_result["ImageConfig"] = {}
            expected_result["Architectures"] = ["x86_64"]
            # Check that the result contains the expected fields (some pro extensions could add additional fields)
            self.assertDictContainsSubset(expected_result, result)

    def test_publish_non_existant_function_version_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(lambda_api.publish_version(self.FUNCTION_NAME).get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result["__type"])
            self.assertEqual(
                self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn(self.FUNCTION_NAME),
                result["message"],
            )

    def test_list_function_versions(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)
            lambda_api.publish_version(self.FUNCTION_NAME)
            lambda_api.publish_version(self.FUNCTION_NAME)

            result = json.loads(lambda_api.list_versions(self.FUNCTION_NAME).get_data())
            for version in result["Versions"]:
                # we need to remove this, since this is random, so we cannot know its value
                version.pop("RevisionId", None)

            latest_version = {}
            latest_version["CodeSize"] = self.CODE_SIZE
            latest_version["CodeSha256"] = self.CODE_SHA_256
            latest_version["FunctionArn"] = (
                str(lambda_api.func_arn(self.FUNCTION_NAME)) + ":$LATEST"
            )
            latest_version["FunctionName"] = str(self.FUNCTION_NAME)
            latest_version["Handler"] = str(self.HANDLER)
            latest_version["Runtime"] = str(self.RUNTIME)
            latest_version["Timeout"] = self.TIMEOUT
            latest_version["Description"] = ""
            latest_version["MemorySize"] = self.MEMORY_SIZE
            latest_version["Role"] = self.ROLE
            latest_version["KMSKeyArn"] = None
            latest_version["VpcConfig"] = None
            latest_version["LastModified"] = isoformat_milliseconds(self.LAST_MODIFIED) + "+0000"
            latest_version["TracingConfig"] = self.TRACING_CONFIG
            latest_version["Version"] = "$LATEST"
            latest_version["State"] = "Active"
            latest_version["LastUpdateStatus"] = "Successful"
            latest_version["PackageType"] = None
            latest_version["ImageConfig"] = {}
            latest_version["Architectures"] = ["x86_64"]
            version1 = dict(latest_version)
            version1["FunctionArn"] = str(lambda_api.func_arn(self.FUNCTION_NAME)) + ":1"
            version1["Version"] = "1"
            expected_versions = sorted(
                [latest_version, version], key=lambda k: str(k.get("Version"))
            )

            # Check if the result contains the same amount of versions and that they contain at least the defined fields
            # (some pro extensions could add additional fields)
            self.assertIn("Versions", result)
            result_versions = result["Versions"]
            self.assertEqual(len(result_versions), len(expected_versions))
            for i in range(len(expected_versions)):
                self.assertDictContainsSubset(expected_versions[i], result_versions[i])

    def test_list_non_existant_function_versions_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(lambda_api.list_versions(self.FUNCTION_NAME).get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result["__type"])
            self.assertEqual(
                self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn(self.FUNCTION_NAME),
                result["message"],
            )

    def test_create_alias(self):
        self._create_function(self.FUNCTION_NAME)
        self.client.post("{0}/functions/{1}/versions".format(API_PATH_ROOT, self.FUNCTION_NAME))

        response = self.client.post(
            "{0}/functions/{1}/aliases".format(API_PATH_ROOT, self.FUNCTION_NAME),
            data=json.dumps({"Name": self.ALIAS_NAME, "FunctionVersion": "1", "Description": ""}),
        )
        result = json.loads(response.get_data())
        result.pop(
            "RevisionId", None
        )  # we need to remove this, since this is random, so we cannot know its value

        expected_result = {
            "AliasArn": lambda_api.func_arn(self.FUNCTION_NAME) + ":" + self.ALIAS_NAME,
            "FunctionVersion": "1",
            "Description": "",
            "Name": self.ALIAS_NAME,
        }
        self.assertDictEqual(expected_result, result)

    def test_create_alias_on_non_existant_function_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(lambda_api.create_alias(self.FUNCTION_NAME).get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result["__type"])
            self.assertEqual(
                self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn(self.FUNCTION_NAME),
                result["message"],
            )

    def test_create_alias_returns_error_if_already_exists(self):
        self._create_function(self.FUNCTION_NAME)
        self.client.post("{0}/functions/{1}/versions".format(API_PATH_ROOT, self.FUNCTION_NAME))
        data = json.dumps({"Name": self.ALIAS_NAME, "FunctionVersion": "1", "Description": ""})
        self.client.post(
            "{0}/functions/{1}/aliases".format(API_PATH_ROOT, self.FUNCTION_NAME),
            data=data,
        )

        response = self.client.post(
            "{0}/functions/{1}/aliases".format(API_PATH_ROOT, self.FUNCTION_NAME),
            data=data,
        )
        result = json.loads(response.get_data())

        alias_arn = lambda_api.func_arn(self.FUNCTION_NAME) + ":" + self.ALIAS_NAME
        self.assertEqual(self.ALIASEXISTS_EXCEPTION, result["__type"])
        self.assertEqual(self.ALIASEXISTS_MESSAGE % alias_arn, result["message"])

    def test_update_alias(self):
        self._create_function(self.FUNCTION_NAME)
        self.client.post("{0}/functions/{1}/versions".format(API_PATH_ROOT, self.FUNCTION_NAME))
        self.client.post(
            "{0}/functions/{1}/aliases".format(API_PATH_ROOT, self.FUNCTION_NAME),
            data=json.dumps({"Name": self.ALIAS_NAME, "FunctionVersion": "1", "Description": ""}),
        )

        response = self.client.put(
            "{0}/functions/{1}/aliases/{2}".format(
                API_PATH_ROOT, self.FUNCTION_NAME, self.ALIAS_NAME
            ),
            data=json.dumps({"FunctionVersion": "$LATEST", "Description": "Test-Description"}),
        )
        result = json.loads(response.get_data())
        result.pop(
            "RevisionId", None
        )  # we need to remove this, since this is random, so we cannot know its value

        expected_result = {
            "AliasArn": lambda_api.func_arn(self.FUNCTION_NAME) + ":" + self.ALIAS_NAME,
            "FunctionVersion": "$LATEST",
            "Description": "Test-Description",
            "Name": self.ALIAS_NAME,
        }
        self.assertDictEqual(expected_result, result)

    def test_update_alias_on_non_existant_function_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(
                lambda_api.update_alias(self.FUNCTION_NAME, self.ALIAS_NAME).get_data()
            )
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result["__type"])
            self.assertEqual(
                self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn(self.FUNCTION_NAME),
                result["message"],
            )

    def test_update_alias_on_non_existant_alias_returns_error(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)
            result = json.loads(
                lambda_api.update_alias(self.FUNCTION_NAME, self.ALIAS_NAME).get_data()
            )
            alias_arn = lambda_api.func_arn(self.FUNCTION_NAME) + ":" + self.ALIAS_NAME
            self.assertEqual(self.ALIASNOTFOUND_EXCEPTION, result["__type"])
            self.assertEqual(self.ALIASNOTFOUND_MESSAGE % alias_arn, result["message"])

    def test_get_alias(self):
        self._create_function(self.FUNCTION_NAME)
        self.client.post("{0}/functions/{1}/versions".format(API_PATH_ROOT, self.FUNCTION_NAME))
        self.client.post(
            "{0}/functions/{1}/aliases".format(API_PATH_ROOT, self.FUNCTION_NAME),
            data=json.dumps({"Name": self.ALIAS_NAME, "FunctionVersion": "1", "Description": ""}),
        )

        response = self.client.get(
            "{0}/functions/{1}/aliases/{2}".format(
                API_PATH_ROOT, self.FUNCTION_NAME, self.ALIAS_NAME
            )
        )
        result = json.loads(response.get_data())
        result.pop(
            "RevisionId", None
        )  # we need to remove this, since this is random, so we cannot know its value

        expected_result = {
            "AliasArn": lambda_api.func_arn(self.FUNCTION_NAME) + ":" + self.ALIAS_NAME,
            "FunctionVersion": "1",
            "Description": "",
            "Name": self.ALIAS_NAME,
        }
        self.assertDictEqual(expected_result, result)

    def test_get_alias_on_non_existant_function_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(
                lambda_api.get_alias(self.FUNCTION_NAME, self.ALIAS_NAME).get_data()
            )
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result["__type"])
            self.assertEqual(
                self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn(self.FUNCTION_NAME),
                result["message"],
            )

    def test_get_alias_on_non_existant_alias_returns_error(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)
            result = json.loads(
                lambda_api.get_alias(self.FUNCTION_NAME, self.ALIAS_NAME).get_data()
            )
            alias_arn = lambda_api.func_arn(self.FUNCTION_NAME) + ":" + self.ALIAS_NAME
            self.assertEqual(self.ALIASNOTFOUND_EXCEPTION, result["__type"])
            self.assertEqual(self.ALIASNOTFOUND_MESSAGE % alias_arn, result["message"])

    def test_list_aliases(self):
        self._create_function(self.FUNCTION_NAME)
        self.client.post("{0}/functions/{1}/versions".format(API_PATH_ROOT, self.FUNCTION_NAME))

        self.client.post(
            "{0}/functions/{1}/aliases".format(API_PATH_ROOT, self.FUNCTION_NAME),
            data=json.dumps({"Name": self.ALIAS2_NAME, "FunctionVersion": "$LATEST"}),
        )
        self.client.post(
            "{0}/functions/{1}/aliases".format(API_PATH_ROOT, self.FUNCTION_NAME),
            data=json.dumps(
                {
                    "Name": self.ALIAS_NAME,
                    "FunctionVersion": "1",
                    "Description": self.ALIAS_NAME,
                }
            ),
        )

        response = self.client.get(
            "{0}/functions/{1}/aliases".format(API_PATH_ROOT, self.FUNCTION_NAME)
        )
        result = json.loads(response.get_data())
        for alias in result["Aliases"]:
            alias.pop(
                "RevisionId", None
            )  # we need to remove this, since this is random, so we cannot know its value
        expected_result = {
            "Aliases": [
                {
                    "AliasArn": lambda_api.func_arn(self.FUNCTION_NAME) + ":" + self.ALIAS_NAME,
                    "FunctionVersion": "1",
                    "Name": self.ALIAS_NAME,
                    "Description": self.ALIAS_NAME,
                },
                {
                    "AliasArn": lambda_api.func_arn(self.FUNCTION_NAME) + ":" + self.ALIAS2_NAME,
                    "FunctionVersion": "$LATEST",
                    "Name": self.ALIAS2_NAME,
                    "Description": "",
                },
            ]
        }
        self.assertDictEqual(expected_result, result)

    def test_list_non_existant_function_aliases_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(lambda_api.list_aliases(self.FUNCTION_NAME).get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result["__type"])
            self.assertEqual(
                self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn(self.FUNCTION_NAME),
                result["message"],
            )

    def test_get_container_name(self):
        executor = lambda_executors.EXECUTOR_CONTAINERS_REUSE
        name = executor.get_container_name(aws_stack.lambda_function_arn("my_function_name"))
        self.assertIn(
            f"_lambda_arn_aws_lambda_{aws_stack.get_region()}_{get_aws_account_id()}_function_my_function_name",
            name,
        )

    def test_concurrency(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)
            # note: PutFunctionConcurrency is mounted at: /2017-10-31
            # NOT API_PATH_ROOT
            # https://docs.aws.amazon.com/lambda/latest/dg/API_PutFunctionConcurrency.html
            concurrency_data = {"ReservedConcurrentExecutions": 10}
            response = self.client.put(
                "/2017-10-31/functions/{0}/concurrency".format(self.FUNCTION_NAME),
                data=json.dumps(concurrency_data),
            )

            result = json.loads(response.get_data())
            self.assertDictEqual(concurrency_data, result)

            response = self.client.get(
                "/2019-09-30/functions/{0}/concurrency".format(self.FUNCTION_NAME)
            )
            self.assertDictEqual(concurrency_data, result)

            response = self.client.delete(
                "/2017-10-31/functions/{0}/concurrency".format(self.FUNCTION_NAME)
            )
            self.assertIsNotNone("ReservedConcurrentExecutions", result)

    def test_concurrency_get_function(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)
            # note: PutFunctionConcurrency is mounted at: /2017-10-31
            # NOT API_PATH_ROOT
            # https://docs.aws.amazon.com/lambda/latest/dg/API_PutFunctionConcurrency.html
            concurrency_data = {"ReservedConcurrentExecutions": 10}
            self.client.put(
                "/2017-10-31/functions/{0}/concurrency".format(self.FUNCTION_NAME),
                data=json.dumps(concurrency_data),
            )

            response = self.client.get(
                "{0}/functions/{1}".format(API_PATH_ROOT, self.FUNCTION_NAME)
            )

            result = json.loads(response.get_data())
            self.assertTrue("Concurrency" in result)
            self.assertDictEqual(concurrency_data, result["Concurrency"])

    def test_list_tags(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME, self.TAGS)
            arn = lambda_api.func_arn(self.FUNCTION_NAME)
            response = self.client.get("{0}/tags/{1}".format(API_PATH_ROOT, arn))
            result = json.loads(response.get_data())
            self.assertTrue("Tags" in result)
            self.assertDictEqual(self.TAGS, result["Tags"])

    def test_tag_resource(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)
            arn = lambda_api.func_arn(self.FUNCTION_NAME)
            response = self.client.get("{0}/tags/{1}".format(API_PATH_ROOT, arn))
            result = json.loads(response.get_data())
            self.assertTrue("Tags" in result)
            self.assertDictEqual({}, result["Tags"])

            self.client.post(
                "{0}/tags/{1}".format(API_PATH_ROOT, arn),
                data=json.dumps({"Tags": self.TAGS}),
            )
            response = self.client.get("{0}/tags/{1}".format(API_PATH_ROOT, arn))
            result = json.loads(response.get_data())
            self.assertTrue("Tags" in result)
            self.assertDictEqual(self.TAGS, result["Tags"])

    def test_tag_non_existent_function_returns_error(self):
        with self.app.test_request_context():
            arn = lambda_api.func_arn("non-existent-function")
            response = self.client.post(
                "{0}/tags/{1}".format(API_PATH_ROOT, arn),
                data=json.dumps({"Tags": self.TAGS}),
            )
            result = json.loads(response.get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result["__type"])
            self.assertEqual(self.RESOURCENOTFOUND_MESSAGE % arn, result["message"])

    def test_untag_resource(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME, tags=self.TAGS)
            arn = lambda_api.func_arn(self.FUNCTION_NAME)
            response = self.client.get("{0}/tags/{1}".format(API_PATH_ROOT, arn))
            result = json.loads(response.get_data())
            self.assertTrue("Tags" in result)
            self.assertDictEqual(self.TAGS, result["Tags"])

            self.client.delete(
                "{0}/tags/{1}".format(API_PATH_ROOT, arn),
                query_string={"tagKeys": "env"},
            )
            response = self.client.get("{0}/tags/{1}".format(API_PATH_ROOT, arn))
            result = json.loads(response.get_data())
            self.assertTrue("Tags" in result)
            self.assertDictEqual({"hello": "world"}, result["Tags"])

    def test_update_configuration(self):
        self._create_function(self.FUNCTION_NAME)

        updated_config = {"Description": "lambda_description"}
        response = json.loads(
            self.client.put(
                "{0}/functions/{1}/configuration".format(API_PATH_ROOT, self.FUNCTION_NAME),
                json=updated_config,
            ).get_data()
        )

        expected_response = {}
        expected_response["LastUpdateStatus"] = "Successful"
        expected_response["FunctionName"] = str(self.FUNCTION_NAME)
        expected_response["Runtime"] = str(self.RUNTIME)
        expected_response["CodeSize"] = self.CODE_SIZE
        expected_response["CodeSha256"] = self.CODE_SHA_256
        expected_response["Handler"] = self.HANDLER
        expected_response.update(updated_config)
        subset = {k: v for k, v in response.items() if k in expected_response.keys()}
        self.assertDictEqual(expected_response, subset)

        get_response = json.loads(
            self.client.get(
                "{0}/functions/{1}/configuration".format(API_PATH_ROOT, self.FUNCTION_NAME)
            ).get_data()
        )
        self.assertDictEqual(response, get_response)

    def test_java_options_empty_return_empty_value(self):
        lambda_executors.config.LAMBDA_JAVA_OPTS = ""
        result = lambda_executors.Util.get_java_opts()
        self.assertFalse(result)

    def test_java_options_with_only_memory_options(self):
        expected = "-Xmx512M"
        result = self.prepare_java_opts(expected)
        self.assertEqual(expected, result)

    def test_java_options_with_memory_options_and_agentlib_option(self):
        expected = ".*transport=dt_socket,server=y,suspend=y,address=[0-9]+"
        result = self.prepare_java_opts(
            "-Xmx512M -agentlib:jdwp=transport=dt_socket,server=y" ",suspend=y,address=_debug_port_"
        )
        self.assertTrue(re.match(expected, result))
        self.assertTrue(lambda_executors.Util.debug_java_port is not False)

    def test_java_options_with_unset_debug_port(self):
        options = [
            "-agentlib:jdwp=transport=dt_socket,server=y,address=_debug_port_,suspend=y",
            "-agentlib:jdwp=transport=dt_socket,server=y,address=localhost:_debug_port_,suspend=y",
            "-agentlib:jdwp=transport=dt_socket,server=y,address=127.0.0.1:_debug_port_,suspend=y",
            "-agentlib:jdwp=transport=dt_socket,server=y,address=*:_debug_port_,suspend=y",
            "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=_debug_port_",
            "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=localhost:_debug_port_",
            "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=127.0.0.1:_debug_port_",
            "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=*:_debug_port_",
        ]

        expected_results = [
            "-agentlib:jdwp=transport=dt_socket,server=y,address=([0-9]+),suspend=y",
            "-agentlib:jdwp=transport=dt_socket,server=y,address=localhost:([0-9]+),suspend=y",
            "-agentlib:jdwp=transport=dt_socket,server=y,address=127.0.0.1:([0-9]+),suspend=y",
            "-agentlib:jdwp=transport=dt_socket,server=y,address=\\*:([0-9]+),suspend=y",
            "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=([0-9]+)",
            "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=localhost:([0-9]+)",
            "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=127.0.0.1:([0-9]+)",
            "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=\\*:([0-9]+)",
        ]

        for i in range(len(options)):
            result = self.prepare_java_opts(options[i])
            m = re.match(expected_results[i], result)
            self.assertTrue(m)
            self.assertEqual(m.groups()[0], lambda_executors.Util.debug_java_port)

    def test_java_options_with_configured_debug_port(self):
        options = [
            "-agentlib:jdwp=transport=dt_socket,server=y,address=1234,suspend=y",
            "-agentlib:jdwp=transport=dt_socket,server=y,address=localhost:1234,suspend=y",
            "-agentlib:jdwp=transport=dt_socket,server=y,address=127.0.0.1:1234,suspend=y",
            "-agentlib:jdwp=transport=dt_socket,server=y,address=*:1234,suspend=y",
            "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=1234",
            "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=localhost:1234",
            "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=127.0.0.1:1234",
            "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=*:1234",
        ]

        for item in options:
            result = self.prepare_java_opts(item)
            self.assertEqual("1234", lambda_executors.Util.debug_java_port)
            self.assertEqual(item, result)

    def prepare_java_opts(self, java_opts):
        lambda_executors.config.LAMBDA_JAVA_OPTS = java_opts
        result = lambda_executors.Util.get_java_opts()
        return result

    def test_get_java_lib_folder_classpath(self):
        jar_file = os.path.join(new_tmp_dir(), "foo.jar")
        save_file(jar_file, "")
        classpath = lambda_executors.Util.get_java_classpath(os.path.dirname(jar_file))
        self.assertIn(".:foo.jar", classpath)
        self.assertIn("*.jar", classpath)

    def test_get_java_lib_folder_classpath_no_directories(self):
        base_dir = new_tmp_dir()
        jar_file = os.path.join(base_dir, "foo.jar")
        save_file(jar_file, "")
        lib_file = os.path.join(base_dir, "lib", "lib.jar")
        mkdir(os.path.dirname(lib_file))
        save_file(lib_file, "")
        classpath = lambda_executors.Util.get_java_classpath(os.path.dirname(jar_file))
        self.assertIn(":foo.jar", classpath)
        self.assertIn("lib/lib.jar:", classpath)
        self.assertIn(":*.jar", classpath)

    def test_get_java_lib_folder_classpath_archive_is_None(self):
        self.assertRaises(ValueError, lambda_executors.Util.get_java_classpath, None)

    @mock.patch("localstack.utils.cloudwatch.cloudwatch_util.store_cloudwatch_logs")
    def test_executor_store_logs_can_handle_milliseconds(self, mock_store_cloudwatch_logs):
        mock_details = mock.Mock()
        t_sec = time.time()  # plain old epoch secs
        t_ms = time.time() * 1000  # epoch ms as a long-int like AWS

        # pass t_ms millisecs to store_cloudwatch_logs
        lambda_utils.store_lambda_logs(mock_details, "mock log output", t_ms)

        # expect the computed log-stream-name to having a prefix matching the date derived from t_sec
        today = datetime.datetime.utcfromtimestamp(t_sec).strftime("%Y/%m/%d")
        log_stream_name = mock_store_cloudwatch_logs.call_args_list[0].args[1]
        parts = log_stream_name.split("/")
        date_part = "/".join(parts[:3])
        self.assertEqual(date_part, today)

    def _create_function(self, function_name, tags=None):
        if tags is None:
            tags = {}
        region = lambda_api.LambdaRegion.get()
        arn = lambda_api.func_arn(function_name)
        region.lambdas[arn] = LambdaFunction(arn)
        region.lambdas[arn].versions = {
            "$LATEST": {
                "CodeSize": self.CODE_SIZE,
                "CodeSha256": self.CODE_SHA_256,
                "RevisionId": self.REVISION_ID,
            }
        }
        region.lambdas[arn].handler = self.HANDLER
        region.lambdas[arn].runtime = self.RUNTIME
        region.lambdas[arn].timeout = self.TIMEOUT
        region.lambdas[arn].tags = tags
        region.lambdas[arn].envvars = {}
        region.lambdas[arn].last_modified = self.LAST_MODIFIED
        region.lambdas[arn].role = self.ROLE
        region.lambdas[arn].memory_size = self.MEMORY_SIZE
        region.lambdas[arn].state = "Active"

    def _update_function_code(self, function_name, tags=None):
        if tags is None:
            tags = {}
        region = lambda_api.LambdaRegion.get()
        arn = lambda_api.func_arn(function_name)
        region.lambdas[arn].versions.update(
            {
                "$LATEST": {
                    "CodeSize": self.CODE_SIZE,
                    "CodeSha256": self.UPDATED_CODE_SHA_256,
                    "RevisionId": self.REVISION_ID,
                }
            }
        )

    def _assert_contained(self, child, parent):
        self.assertTrue(set(child.items()).issubset(set(parent.items())))

    @mock.patch("tempfile.NamedTemporaryFile")
    def test_lambda_output(self, temp):
        stderr = """START RequestId: 14c6eaeb-9183-4461-b520-10c4c64a2b07 Version: $LATEST
        2022-01-27T12:57:39.071Z	14c6eaeb-9183-4461-b520-10c4c64a2b07 INFO {}
        2022-01-27T12:57:39.071Z	14c6eaeb-9183-4461-b520-10c4c64a2b07 INFO {
        callbackWaitsForEmptyEventLoop: [Getter/Setter], succeed: [Function (anonymous)],
        fail: [Function (anonymous)], done: [Function (anonymous)], functionVersion: '$LATEST',
        functionName: 'hello', memoryLimitInMB: '128', logGroupName: '/aws/lambda/hello',
        logStreamName: '2022/01/27/[$LATEST]44deffbc11404f459e2cf38bb2fae611', clientContext:
        undefined, identity: undefined, invokedFunctionArn:
        'arn:aws:lambda:eu-west-1:659676821118:function:hello', awsRequestId:
        '14c6eaeb-9183-4461-b520-10c4c64a2b07', getRemainingTimeInMillis: [Function:
        getRemainingTimeInMillis] } END RequestId: 14c6eaeb-9183-4461-b520-10c4c64a2b07 REPORT
        RequestId: 14c6eaeb-9183-4461-b520-10c4c64a2b07	Duration: 1.61 ms	Billed Duration: 2
        ms	Memory Size: 128 MB	Max Memory Used: 58 MB """

        output = OutputLog(stdout='{"hello":"world"}', stderr=stderr)
        self.assertEqual('{"hello":"world"}', output.stdout_formatted())
        self.assertEqual("START...", output.stderr_formatted(truncated_to=5))

        output.output_file()

        temp.assert_called_once_with(
            dir=config.dirs.tmp, delete=False, suffix=".log", prefix="lambda_"
        )


class TestLambdaEventInvokeConfig(unittest.TestCase):
    CODE_SIZE = 50
    CODE_SHA_256 = "/u60ZpAA9bzZPVwb8d4390i5oqP1YAObUwV03CZvsWA="
    MEMORY_SIZE = 128
    ROLE = lambda_api.LAMBDA_TEST_ROLE
    LAST_MODIFIED = datetime.datetime.utcnow()
    REVISION_ID = "e54dbcf8-e3ef-44ab-9af7-8dbef510608a"
    HANDLER = "index.handler"
    RUNTIME = "node.js4.3"
    TIMEOUT = 60
    FUNCTION_NAME = "test1"
    RETRY_ATTEMPTS = 5
    EVENT_AGE = 360
    DL_QUEUE = "arn:aws:sqs:us-east-1:000000000000:dlQueue"
    LAMBDA_OBJ = LambdaFunction(lambda_api.func_arn("test1"))

    def _create_function(self, function_name, tags=None):
        if tags is None:
            tags = {}
        self.LAMBDA_OBJ.versions = {
            "$LATEST": {
                "CodeSize": self.CODE_SIZE,
                "CodeSha256": self.CODE_SHA_256,
                "RevisionId": self.REVISION_ID,
            }
        }
        self.LAMBDA_OBJ.handler = self.HANDLER
        self.LAMBDA_OBJ.runtime = self.RUNTIME
        self.LAMBDA_OBJ.timeout = self.TIMEOUT
        self.LAMBDA_OBJ.tags = tags
        self.LAMBDA_OBJ.envvars = {}
        self.LAMBDA_OBJ.last_modified = self.LAST_MODIFIED
        self.LAMBDA_OBJ.role = self.ROLE
        self.LAMBDA_OBJ.memory_size = self.MEMORY_SIZE

    # TODO: remove this test case. Already added it in integration test case
    def test_put_function_event_invoke_config(self):
        # creating a lambda function
        self._create_function(self.FUNCTION_NAME)

        # calling put_function_event_invoke_config
        payload = {
            "DestinationConfig": {"OnFailure": {"Destination": self.DL_QUEUE}},
            "MaximumEventAgeInSeconds": self.EVENT_AGE,
            "MaximumRetryAttempts": self.RETRY_ATTEMPTS,
        }
        response = self.LAMBDA_OBJ.put_function_event_invoke_config(payload)
        # checking if response is not None
        self.assertIsNotNone(response)

        # calling get_function_event_invoke_config
        response = self.LAMBDA_OBJ.get_function_event_invoke_config()

        # verifying set values
        self.assertEqual(self.LAMBDA_OBJ.id, response["FunctionArn"])
        self.assertEqual(self.RETRY_ATTEMPTS, response["MaximumRetryAttempts"])
        self.assertEqual(self.EVENT_AGE, response["MaximumEventAgeInSeconds"])
        self.assertEqual(self.DL_QUEUE, response["DestinationConfig"]["OnFailure"]["Destination"])


class TestLambdaUtils:
    def test_host_path_for_path_in_docker_windows(self):
        with mock.patch(
            "localstack.services.awslambda.lambda_executors.get_default_volume_dir_mount"
        ) as get_volume, mock.patch("localstack.config.is_in_docker", True):
            get_volume.return_value = VolumeInfo(
                type="bind",
                source=r"C:\Users\localstack\volume\mount",
                destination="/var/lib/localstack",
                mode="rw",
                rw=True,
                propagation="rprivate",
            )
            result = Util.get_host_path_for_path_in_docker("/var/lib/localstack/some/test/file")
            get_volume.assert_called_once()
            # this path style is kinda weird, but windows will accept it - no need for manual conversion of / to \
            assert result == r"C:\Users\localstack\volume\mount/some/test/file"

    def test_host_path_for_path_in_docker_linux(self):
        with mock.patch(
            "localstack.services.awslambda.lambda_executors.get_default_volume_dir_mount"
        ) as get_volume, mock.patch("localstack.config.is_in_docker", True):
            get_volume.return_value = VolumeInfo(
                type="bind",
                source="/home/some-user/.cache/localstack/volume",
                destination="/var/lib/localstack",
                mode="rw",
                rw=True,
                propagation="rprivate",
            )
            result = Util.get_host_path_for_path_in_docker("/var/lib/localstack/some/test/file")
            get_volume.assert_called_once()
            assert result == "/home/some-user/.cache/localstack/volume/some/test/file"

    def test_host_path_for_path_in_docker_linux_volume_dir(self):
        with mock.patch(
            "localstack.services.awslambda.lambda_executors.get_default_volume_dir_mount"
        ) as get_volume, mock.patch("localstack.config.is_in_docker", True):
            get_volume.return_value = VolumeInfo(
                type="bind",
                source="/home/some-user/.cache/localstack/volume",
                destination="/var/lib/localstack",
                mode="rw",
                rw=True,
                propagation="rprivate",
            )
            result = Util.get_host_path_for_path_in_docker("/var/lib/localstack")
            get_volume.assert_called_once()
            assert result == "/home/some-user/.cache/localstack/volume"

    def test_host_path_for_path_in_docker_linux_wrong_path(self):
        with mock.patch(
            "localstack.services.awslambda.lambda_executors.get_default_volume_dir_mount"
        ) as get_volume, mock.patch("localstack.config.is_in_docker", True):
            get_volume.return_value = VolumeInfo(
                type="bind",
                source="/home/some-user/.cache/localstack/volume",
                destination="/var/lib/localstack",
                mode="rw",
                rw=True,
                propagation="rprivate",
            )
            result = Util.get_host_path_for_path_in_docker("/var/lib/localstacktest")
            get_volume.assert_called_once()
            assert result == "/var/lib/localstacktest"
            result = Util.get_host_path_for_path_in_docker("/etc/some/path")
            assert result == "/etc/some/path"

    def test_lambda_policy_name(self):
        func_name = "lambda1"
        policy_name1 = get_lambda_policy_name(func_name)
        policy_name2 = get_lambda_policy_name(lambda_api.func_arn(func_name))
        assert func_name in policy_name1
        assert policy_name1 == policy_name2
