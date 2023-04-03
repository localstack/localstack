import base64
import json
import logging
import os
import threading
import time
import unittest

import pytest
from botocore.exceptions import ClientError
from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

import localstack.services.awslambda.lambda_api
from localstack import config
from localstack.services.awslambda import lambda_api, lambda_executors
from localstack.services.awslambda.lambda_api import do_set_function_code, use_docker
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON39
from localstack.testing.aws.lambda_utils import is_new_provider
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.files import load_file
from localstack.utils.functions import run_safe
from localstack.utils.strings import short_uid, to_bytes, to_str
from localstack.utils.sync import poll_condition, retry
from localstack.utils.testutil import create_lambda_archive

from .test_lambda import (
    TEST_LAMBDA_ENV,
    TEST_LAMBDA_LIBS,
    TEST_LAMBDA_PYTHON,
    TEST_LAMBDA_PYTHON_ECHO,
)

# TestLocalLambda variables
THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON3_MULTIPLE_CREATE1 = os.path.join(
    THIS_FOLDER, "functions", "python3", "lambda1", "lambda1.zip"
)
TEST_LAMBDA_PYTHON3_MULTIPLE_CREATE2 = os.path.join(
    THIS_FOLDER, "functions", "python3", "lambda2", "lambda2.zip"
)

LOG = logging.getLogger(__name__)

pytestmark = pytest.mark.skipif(
    condition=is_new_provider(), reason="only relevant for old provider"
)


class TestLambdaFallbackUrl(unittest.TestCase):
    @staticmethod
    def _run_forward_to_fallback_url(url, fallback=True, lambda_name=None, num_requests=3):
        lambda_client = aws_stack.create_external_boto_client("lambda")
        if fallback:
            config.LAMBDA_FALLBACK_URL = url
        else:
            config.LAMBDA_FORWARD_URL = url
        try:
            result = []
            for i in range(num_requests):
                lambda_name = lambda_name or "non-existing-lambda-%s" % i
                ctx = {"env": "test"}
                tmp = lambda_client.invoke(
                    FunctionName=lambda_name,
                    Payload=b'{"foo":"bar"}',
                    InvocationType="RequestResponse",
                    ClientContext=to_str(base64.b64encode(to_bytes(json.dumps(ctx)))),
                )
            result.append(tmp)
            return result
        finally:
            if fallback:
                config.LAMBDA_FALLBACK_URL = ""
            else:
                config.LAMBDA_FORWARD_URL = ""

    def test_forward_to_fallback_url_dynamodb(self):
        db_table = "lambda-records"
        ddb_client = aws_stack.create_external_boto_client("dynamodb")

        def num_items():
            return len((run_safe(ddb_client.scan, TableName=db_table) or {"Items": []})["Items"])

        items_before = num_items()
        self._run_forward_to_fallback_url("dynamodb://%s" % db_table)
        items_after = num_items()
        self.assertEqual(items_before + 3, items_after)

    def test_forward_to_fallback_url_http(self):
        lambda_client = aws_stack.create_external_boto_client("lambda")
        lambda_result = {"result": "test123"}

        def _handler(_request: Request):
            return Response(json.dumps(lambda_result), mimetype="application/json")

        # using pytest HTTPServer instead of the fixture because this test is still based on unittest
        with HTTPServer() as server:

            server.expect_request("").respond_with_handler(_handler)
            http_endpoint = server.url_for("/")

            # test 1: forward to LAMBDA_FALLBACK_URL
            self._run_forward_to_fallback_url(http_endpoint)

            poll_condition(lambda: len(server.log) >= 3, timeout=10)

            for request, _ in server.log:
                # event = request.get_json(force=True)
                self.assertIn("non-existing-lambda", request.headers["lambda-function-name"])

            self.assertEqual(3, len(server.log))
            server.clear_log()

            try:
                # create test Lambda
                lambda_name = f"test-{short_uid()}"
                testutil.create_lambda_function(
                    handler_file=TEST_LAMBDA_PYTHON,
                    func_name=lambda_name,
                    libs=TEST_LAMBDA_LIBS,
                )
                lambda_client.get_waiter("function_active_v2").wait(FunctionName=lambda_name)

                # test 2: forward to LAMBDA_FORWARD_URL
                inv_results = self._run_forward_to_fallback_url(
                    http_endpoint, lambda_name=lambda_name, fallback=False
                )

                poll_condition(lambda: len(server.log) >= 3, timeout=10)

                for request, _ in server.log:
                    event = request.get_json(force=True)
                    headers = request.headers
                    self.assertIn("/lambda/", headers["Authorization"])
                    self.assertEqual("POST", request.method)
                    self.assertIn(f"/functions/{lambda_name}/invocations", request.path)
                    self.assertTrue(headers.get("X-Amz-Client-Context"))
                    self.assertEqual("RequestResponse", headers.get("X-Amz-Invocation-Type"))
                    self.assertEqual({"foo": "bar"}, event)

                self.assertEqual(3, len(server.log))
                server.clear_log()

                # assert result payload matches
                response_payload = inv_results[0]["Payload"].read()
                self.assertEqual(lambda_result, json.loads(response_payload))
            finally:
                # clean up / shutdown
                lambda_client.delete_function(FunctionName=lambda_name)

    def test_adding_fallback_function_name_in_headers(self):
        lambda_client = aws_stack.create_external_boto_client("lambda")
        ddb_client = aws_stack.create_external_boto_client("dynamodb")

        db_table = "lambda-records"
        config.LAMBDA_FALLBACK_URL = f"dynamodb://{db_table}"

        lambda_client.invoke(
            FunctionName="non-existing-lambda",
            Payload=b"{}",
            InvocationType="RequestResponse",
        )

        def check_item():
            result = run_safe(ddb_client.scan, TableName=db_table)
            self.assertEqual("non-existing-lambda", result["Items"][0]["function_name"]["S"])

        retry(check_item)


class TestDockerExecutors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lambda_client = aws_stack.create_external_boto_client("lambda")
        cls.s3_client = aws_stack.create_external_boto_client("s3")

    @pytest.mark.skipif(not use_docker(), reason="Only applicable with docker executor")
    def test_additional_docker_flags(self):
        flags_before = config.LAMBDA_DOCKER_FLAGS
        env_value = short_uid()
        config.LAMBDA_DOCKER_FLAGS = f"-e Hello={env_value}"
        function_name = "flags-{}".format(short_uid())

        try:
            testutil.create_lambda_function(
                handler_file=TEST_LAMBDA_ENV,
                libs=TEST_LAMBDA_LIBS,
                func_name=function_name,
            )
            lambda_client = aws_stack.create_external_boto_client("lambda")
            lambda_client.get_waiter("function_active_v2").wait(FunctionName=function_name)
            result = lambda_client.invoke(FunctionName=function_name, Payload="{}")
            self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])
            result_data = result["Payload"].read()
            result_data = json.loads(to_str(result_data))
            self.assertEqual({"Hello": env_value}, result_data)
        finally:
            config.LAMBDA_DOCKER_FLAGS = flags_before

        # clean up
        lambda_client.delete_function(FunctionName=function_name)

    def test_code_updated_on_redeployment(self):
        lambda_api.LAMBDA_EXECUTOR.cleanup()

        func_name = "test_code_updated_on_redeployment"

        # deploy function for the first time
        testutil.create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_ENV,
            libs=TEST_LAMBDA_LIBS,
            envvars={"Hello": "World"},
        )
        self.lambda_client.get_waiter("function_active_v2").wait(FunctionName=func_name)

        # test first invocation
        result = self.lambda_client.invoke(FunctionName=func_name, Payload=b"{}")
        payload = json.loads(to_str(result["Payload"].read()))

        assert payload["Hello"] == "World"

        # replacement code
        updated_handler = "handler = lambda event, context: {'Hello': 'Elon Musk'}"
        updated_handler = testutil.create_lambda_archive(
            updated_handler, libs=TEST_LAMBDA_LIBS, get_content=True
        )
        self.lambda_client.update_function_code(FunctionName=func_name, ZipFile=updated_handler)

        # second invocation should exec updated lambda code
        result = self.lambda_client.invoke(FunctionName=func_name, Payload=b"{}")
        payload = json.loads(to_str(result["Payload"].read()))

        assert payload["Hello"] == "Elon Musk"

    @pytest.mark.skipif(
        condition=not isinstance(
            lambda_api.LAMBDA_EXECUTOR, lambda_executors.LambdaExecutorReuseContainers
        ),
        reason="Test only applicable if docker-reuse executor is selected",
    )
    def test_prime_and_destroy_containers(self):
        executor = lambda_api.LAMBDA_EXECUTOR
        func_name = f"test_prime_and_destroy_containers_{short_uid()}"
        func_arn = lambda_api.func_arn(func_name)

        # make sure existing containers are gone
        executor.cleanup()
        self.assertEqual(0, len(executor.get_all_container_names()))

        # deploy and invoke lambda without Docker
        testutil.create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_ENV,
            libs=TEST_LAMBDA_LIBS,
            envvars={"Hello": "World"},
        )
        self.lambda_client.get_waiter("function_active_v2").wait(FunctionName=func_name)

        self.assertEqual(0, len(executor.get_all_container_names()))
        self.assertDictEqual({}, executor.function_invoke_times)

        # invoke a few times.
        durations = []
        num_iterations = 3

        for i in range(0, num_iterations + 1):
            prev_invoke_time = None
            if i > 0:
                prev_invoke_time = executor.function_invoke_times[func_arn]

            start_time = time.time()
            self.lambda_client.invoke(FunctionName=func_name, Payload=b"{}")
            duration = time.time() - start_time

            self.assertEqual(1, len(executor.get_all_container_names()))

            # ensure the last invoke time is being updated properly.
            if i > 0:
                self.assertGreater(executor.function_invoke_times[func_arn], prev_invoke_time)
            else:
                self.assertGreater(executor.function_invoke_times[func_arn], 0)

            durations.append(duration)

        # the first call would have created the container. subsequent calls would reuse and be faster.
        for i in range(1, num_iterations + 1):
            self.assertLess(durations[i], durations[0])

        status = executor.get_docker_container_status(func_arn)
        self.assertEqual(1, status)

        container_network = executor.get_docker_container_network(func_arn)
        self.assertEqual("bridge", container_network)

        executor.cleanup()
        status = executor.get_docker_container_status(func_arn)
        self.assertEqual(0, status)

        self.assertEqual(0, len(executor.get_all_container_names()))

        # clean up
        testutil.delete_lambda_function(func_name)

    @pytest.mark.skipif(
        condition=not isinstance(
            lambda_api.LAMBDA_EXECUTOR, lambda_executors.LambdaExecutorReuseContainers
        ),
        reason="Test only applicable if docker-reuse executor is selected",
    )
    def test_destroy_idle_containers(self):
        executor = lambda_api.LAMBDA_EXECUTOR
        func_name = "test_destroy_idle_containers"
        func_arn = lambda_api.func_arn(func_name)

        # make sure existing containers are gone
        executor.destroy_existing_docker_containers()
        self.assertEqual(0, len(executor.get_all_container_names()))

        # deploy and invoke lambda without Docker
        testutil.create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_ENV,
            libs=TEST_LAMBDA_LIBS,
            envvars={"Hello": "World"},
        )
        self.lambda_client.get_waiter("function_active_v2").wait(FunctionName=func_name)

        self.assertEqual(0, len(executor.get_all_container_names()))

        self.lambda_client.invoke(FunctionName=func_name, Payload=b"{}")
        self.assertEqual(1, len(executor.get_all_container_names()))

        # try to destroy idle containers.
        executor.idle_container_destroyer()
        self.assertEqual(1, len(executor.get_all_container_names()))

        # simulate an idle container
        executor.function_invoke_times[func_arn] = (
            int(time.time() * 1000) - lambda_executors.MAX_CONTAINER_IDLE_TIME_MS
        )
        executor.idle_container_destroyer()

        def assert_container_destroyed():
            self.assertEqual(0, len(executor.get_all_container_names()))

        retry(assert_container_destroyed, retries=3)

        # clean up
        testutil.delete_lambda_function(func_name)


class TestLocalExecutors(unittest.TestCase):
    def test_python3_runtime_multiple_create_with_conflicting_module(self):
        lambda_client = aws_stack.create_external_boto_client("lambda")
        original_do_use_docker = lambda_api.DO_USE_DOCKER
        try:
            # always use the local runner
            lambda_api.DO_USE_DOCKER = False

            python3_with_settings1 = load_file(TEST_LAMBDA_PYTHON3_MULTIPLE_CREATE1, mode="rb")
            python3_with_settings2 = load_file(TEST_LAMBDA_PYTHON3_MULTIPLE_CREATE2, mode="rb")

            lambda_name1 = "test1-%s" % short_uid()
            testutil.create_lambda_function(
                func_name=lambda_name1,
                zip_file=python3_with_settings1,
                runtime=LAMBDA_RUNTIME_PYTHON39,
                handler="handler1.handler",
            )
            lambda_client.get_waiter("function_active_v2").wait(FunctionName=lambda_name1)

            lambda_name2 = "test2-%s" % short_uid()
            testutil.create_lambda_function(
                func_name=lambda_name2,
                zip_file=python3_with_settings2,
                runtime=LAMBDA_RUNTIME_PYTHON39,
                handler="handler2.handler",
            )
            lambda_client.get_waiter("function_active_v2").wait(FunctionName=lambda_name2)

            result1 = lambda_client.invoke(FunctionName=lambda_name1, Payload=b"{}")
            result_data1 = result1["Payload"].read()

            result2 = lambda_client.invoke(FunctionName=lambda_name2, Payload=b"{}")
            result_data2 = result2["Payload"].read()

            self.assertEqual(200, result1["StatusCode"])
            self.assertIn("setting1", to_str(result_data1))

            self.assertEqual(200, result2["StatusCode"])
            self.assertIn("setting2", to_str(result_data2))

            # clean up
            testutil.delete_lambda_function(lambda_name1)
            testutil.delete_lambda_function(lambda_name2)
        finally:
            lambda_api.DO_USE_DOCKER = original_do_use_docker


class TestFunctionStates:
    def test_invoke_failure_when_state_pending(self, lambda_su_role, monkeypatch, aws_client):
        """Tests if a lambda invocation fails if state is pending"""
        function_name = f"test-function-{short_uid()}"
        zip_file = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)

        function_code_set = threading.Event()

        def _do_set_function_code(*args, **kwargs):
            result = do_set_function_code(*args, **kwargs)
            function_code_set.wait()
            return result

        monkeypatch.setattr(
            localstack.services.awslambda.lambda_api, "do_set_function_code", _do_set_function_code
        )
        try:
            response = aws_client.awslambda.create_function(
                FunctionName=function_name,
                Runtime="python3.9",
                Handler="handler.handler",
                Role=lambda_su_role,
                Code={"ZipFile": zip_file},
            )

            assert response["State"] == "Pending"

            with pytest.raises(ClientError) as e:
                aws_client.awslambda.invoke(FunctionName=function_name, Payload=b"{}")

            assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 409
            assert e.match("ResourceConflictException")
            assert e.match(
                "The operation cannot be performed at this time. The function is currently in the following state: Pending"
            )

            # let function move to active
            function_code_set.set()

            # lambda has to get active at some point
            def _check_lambda_state():
                response = aws_client.awslambda.get_function(FunctionName=function_name)
                assert response["Configuration"]["State"] == "Active"
                return response

            retry(_check_lambda_state)
            aws_client.awslambda.invoke(FunctionName=function_name, Payload=b"{}")
        finally:
            try:
                aws_client.awslambda.delete_function(FunctionName=function_name)
            except Exception:
                LOG.debug("Unable to delete function %s", function_name)
