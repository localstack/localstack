import base64
import json
import logging
import os
import threading
import time

import pytest
from botocore.exceptions import ClientError
from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

import localstack.services.lambda_.legacy.lambda_api
from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME
from localstack.services.lambda_.lambda_utils import LAMBDA_RUNTIME_PYTHON39
from localstack.services.lambda_.legacy import lambda_api, lambda_executors
from localstack.services.lambda_.legacy.lambda_api import do_set_function_code, use_docker
from localstack.testing.aws.lambda_utils import is_new_provider
from localstack.testing.pytest import markers
from localstack.utils import testutil
from localstack.utils.files import load_file
from localstack.utils.functions import run_safe
from localstack.utils.strings import short_uid, to_bytes, to_str
from localstack.utils.sync import poll_condition, retry
from localstack.utils.testutil import create_lambda_archive

from .test_lambda import (
    TEST_LAMBDA_ENV,
    TEST_LAMBDA_LIBS,
    TEST_LAMBDA_NODEJS_ECHO,
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


class TestLambdaFallbackUrl:
    @staticmethod
    def _run_forward_to_fallback_url(
        lambda_client, url, fallback=True, lambda_name=None, num_requests=3
    ):
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

    @markers.aws.only_localstack
    def test_forward_to_fallback_url_dynamodb(self, aws_client):
        db_table = f"lambda-records-{short_uid()}"
        ddb_client = aws_client.dynamodb

        def num_items():
            return len((run_safe(ddb_client.scan, TableName=db_table) or {"Items": []})["Items"])

        items_before = num_items()
        self._run_forward_to_fallback_url(aws_client.lambda_, "dynamodb://%s" % db_table)
        items_after = num_items()
        assert items_before + 3 == items_after

    @markers.aws.only_localstack
    def test_forward_to_fallback_url_http(self, aws_client):
        lambda_client = aws_client.lambda_
        lambda_result = {"result": "test123"}

        def _handler(_request: Request):
            return Response(json.dumps(lambda_result), mimetype="application/json")

        # using pytest HTTPServer instead of the fixture because this test is still based on unittest
        with HTTPServer() as server:
            server.expect_request("").respond_with_handler(_handler)
            http_endpoint = server.url_for("/")

            # test 1: forward to LAMBDA_FALLBACK_URL
            self._run_forward_to_fallback_url(aws_client.lambda_, http_endpoint)

            poll_condition(lambda: len(server.log) >= 3, timeout=10)

            for request, _ in server.log:
                # event = request.get_json(force=True)
                assert "non-existing-lambda" in request.headers["lambda-function-name"]

            assert 3 == len(server.log)
            server.clear_log()

            try:
                # create test Lambda
                lambda_name = f"test-{short_uid()}"
                testutil.create_lambda_function(
                    handler_file=TEST_LAMBDA_PYTHON,
                    func_name=lambda_name,
                    libs=TEST_LAMBDA_LIBS,
                    client=aws_client.lambda_,
                )
                lambda_client.get_waiter("function_active_v2").wait(FunctionName=lambda_name)

                # test 2: forward to LAMBDA_FORWARD_URL
                inv_results = self._run_forward_to_fallback_url(
                    aws_client.lambda_, http_endpoint, lambda_name=lambda_name, fallback=False
                )

                poll_condition(lambda: len(server.log) >= 3, timeout=10)

                for request, _ in server.log:
                    event = request.get_json(force=True)
                    headers = request.headers
                    assert "/lambda/" in headers["Authorization"]
                    assert "POST" == request.method
                    assert f"/functions/{lambda_name}/invocations" in request.path
                    assert headers.get("X-Amz-Client-Context")
                    assert "RequestResponse" == headers.get("X-Amz-Invocation-Type")
                    assert {"foo": "bar"} == event

                assert 3 == len(server.log)
                server.clear_log()

                # assert result payload matches
                response_payload = inv_results[0]["Payload"].read()
                assert lambda_result == json.loads(response_payload)
            finally:
                # clean up / shutdown
                lambda_client.delete_function(FunctionName=lambda_name)

    @markers.aws.only_localstack
    def test_adding_fallback_function_name_in_headers(self, aws_client):
        lambda_client = aws_client.lambda_
        ddb_client = aws_client.dynamodb

        db_table = f"lambda-records-{short_uid()}"
        config.LAMBDA_FALLBACK_URL = f"dynamodb://{db_table}"

        lambda_client.invoke(
            FunctionName="invalid-lambda",
            Payload=b"{}",
            InvocationType="RequestResponse",
        )

        def check_item():
            result = run_safe(ddb_client.scan, TableName=db_table)
            assert "invalid-lambda" == result["Items"][0]["function_name"]["S"]

        retry(check_item)


class TestDockerExecutors:
    @pytest.mark.skipif(not use_docker(), reason="Only applicable with docker executor")
    @markers.aws.only_localstack
    def test_additional_docker_flags(self, aws_client):
        flags_before = config.LAMBDA_DOCKER_FLAGS
        env_value = short_uid()
        config.LAMBDA_DOCKER_FLAGS = f"-e Hello={env_value}"
        function_name = "flags-{}".format(short_uid())

        try:
            testutil.create_lambda_function(
                handler_file=TEST_LAMBDA_ENV,
                libs=TEST_LAMBDA_LIBS,
                func_name=function_name,
                client=aws_client.lambda_,
            )
            lambda_client = aws_client.lambda_
            lambda_client.get_waiter("function_active_v2").wait(FunctionName=function_name)
            result = lambda_client.invoke(FunctionName=function_name, Payload="{}")
            assert 200 == result["ResponseMetadata"]["HTTPStatusCode"]
            result_data = result["Payload"].read()
            result_data = json.loads(to_str(result_data))
            assert {"Hello": env_value} == result_data
        finally:
            config.LAMBDA_DOCKER_FLAGS = flags_before

        # clean up
        lambda_client.delete_function(FunctionName=function_name)

    @markers.aws.only_localstack
    def test_code_updated_on_redeployment(self, aws_client):
        lambda_api.LAMBDA_EXECUTOR.cleanup()

        func_name = "test_code_updated_on_redeployment"

        # deploy function for the first time
        testutil.create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_ENV,
            libs=TEST_LAMBDA_LIBS,
            envvars={"Hello": "World"},
            client=aws_client.lambda_,
        )
        aws_client.lambda_.get_waiter("function_active_v2").wait(FunctionName=func_name)

        # test first invocation
        result = aws_client.lambda_.invoke(FunctionName=func_name, Payload=b"{}")
        payload = json.loads(to_str(result["Payload"].read()))

        assert payload["Hello"] == "World"

        # replacement code
        updated_handler = "handler = lambda event, context: {'Hello': 'Elon Musk'}"
        updated_handler = testutil.create_lambda_archive(
            updated_handler, libs=TEST_LAMBDA_LIBS, get_content=True
        )
        aws_client.lambda_.update_function_code(FunctionName=func_name, ZipFile=updated_handler)

        # second invocation should exec updated lambda code
        result = aws_client.lambda_.invoke(FunctionName=func_name, Payload=b"{}")
        payload = json.loads(to_str(result["Payload"].read()))

        assert payload["Hello"] == "Elon Musk"

    @pytest.mark.skipif(
        condition=not isinstance(
            lambda_api.LAMBDA_EXECUTOR, lambda_executors.LambdaExecutorReuseContainers
        ),
        reason="Test only applicable if docker-reuse executor is selected",
    )
    @markers.aws.only_localstack
    def test_prime_and_destroy_containers(self, aws_client):
        executor = lambda_api.LAMBDA_EXECUTOR
        func_name = f"test_prime_and_destroy_containers_{short_uid()}"
        func_arn = lambda_api.func_arn(TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME, func_name)

        # make sure existing containers are gone
        executor.cleanup()
        assert 0 == len(executor.get_all_container_names())

        # deploy and invoke lambda without Docker
        testutil.create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_ENV,
            libs=TEST_LAMBDA_LIBS,
            envvars={"Hello": "World"},
            client=aws_client.lambda_,
        )
        aws_client.lambda_.get_waiter("function_active_v2").wait(FunctionName=func_name)

        assert 0 == len(executor.get_all_container_names())
        assert {} == executor.function_invoke_times

        # invoke a few times.
        durations = []
        num_iterations = 3

        for i in range(0, num_iterations + 1):
            prev_invoke_time = None
            if i > 0:
                prev_invoke_time = executor.function_invoke_times[func_arn]

            start_time = time.time()
            aws_client.lambda_.invoke(FunctionName=func_name, Payload=b"{}")
            duration = time.time() - start_time

            assert 1 == len(executor.get_all_container_names())

            # ensure the last invoke time is being updated properly.
            if i > 0:
                assert executor.function_invoke_times[func_arn] > prev_invoke_time
            else:
                assert executor.function_invoke_times[func_arn] > 0

            durations.append(duration)

        # the first call would have created the container. subsequent calls would reuse and be faster.
        for i in range(1, num_iterations + 1):
            assert durations[i] < durations[0]

        status = executor.get_docker_container_status(func_arn)
        assert 1 == status

        container_network = executor.get_docker_container_network(func_arn)
        assert "bridge" == container_network

        executor.cleanup()
        status = executor.get_docker_container_status(func_arn)
        assert 0 == status

        assert 0 == len(executor.get_all_container_names())

        # clean up
        aws_client.lambda_.delete_function(FunctionName=func_name)

    @pytest.mark.skipif(
        condition=not isinstance(
            lambda_api.LAMBDA_EXECUTOR, lambda_executors.LambdaExecutorReuseContainers
        ),
        reason="Test only applicable if docker-reuse executor is selected",
    )
    @markers.aws.only_localstack
    def test_destroy_idle_containers(self, aws_client):
        executor = lambda_api.LAMBDA_EXECUTOR
        func_name = "test_destroy_idle_containers"
        func_arn = lambda_api.func_arn(TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME, func_name)

        # make sure existing containers are gone
        executor.destroy_existing_docker_containers()
        assert 0 == len(executor.get_all_container_names())

        # deploy and invoke lambda without Docker
        testutil.create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_ENV,
            libs=TEST_LAMBDA_LIBS,
            envvars={"Hello": "World"},
            client=aws_client.lambda_,
        )
        aws_client.lambda_.get_waiter("function_active_v2").wait(FunctionName=func_name)

        assert 0 == len(executor.get_all_container_names())

        aws_client.lambda_.invoke(FunctionName=func_name, Payload=b"{}")
        assert 1 == len(executor.get_all_container_names())

        # try to destroy idle containers.
        executor.idle_container_destroyer()
        assert 1 == len(executor.get_all_container_names())

        # simulate an idle container
        executor.function_invoke_times[func_arn] = (
            int(time.time() * 1000) - lambda_executors.MAX_CONTAINER_IDLE_TIME_MS
        )
        executor.idle_container_destroyer()

        def assert_container_destroyed():
            assert 0 == len(executor.get_all_container_names())

        retry(assert_container_destroyed, retries=3)

        # clean up
        aws_client.lambda_.delete_function(FunctionName=func_name)

    @pytest.mark.skipif(
        condition=not isinstance(
            lambda_api.LAMBDA_EXECUTOR, lambda_executors.LambdaExecutorReuseContainers
        ),
        reason="Test only applicable if docker-reuse executor is selected",
    )
    @markers.aws.only_localstack
    def test_logresult_more_than_4k_characters(self, aws_client):
        lambda_api.LAMBDA_EXECUTOR.cleanup()

        func_name = "test_logresult_more_than_4k_characters"

        testutil.create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_NODEJS_ECHO,
            runtime="nodejs16.x",
            client=aws_client.lambda_,
        )
        aws_client.lambda_.get_waiter("function_active_v2").wait(FunctionName=func_name)

        result = aws_client.lambda_.invoke(
            FunctionName=func_name, Payload=('{"key":"%s"}' % ("😀" + " " * 4091))
        )
        assert "FunctionError" not in result

        # clean up
        aws_client.lambda_.delete_function(FunctionName=func_name)


class TestLocalExecutors:
    @markers.aws.only_localstack
    def test_python3_runtime_multiple_create_with_conflicting_module(self, aws_client):
        lambda_client = aws_client.lambda_
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
                client=aws_client.lambda_,
            )
            lambda_client.get_waiter("function_active_v2").wait(FunctionName=lambda_name1)

            lambda_name2 = "test2-%s" % short_uid()
            testutil.create_lambda_function(
                func_name=lambda_name2,
                zip_file=python3_with_settings2,
                runtime=LAMBDA_RUNTIME_PYTHON39,
                handler="handler2.handler",
                client=aws_client.lambda_,
            )
            lambda_client.get_waiter("function_active_v2").wait(FunctionName=lambda_name2)

            result1 = lambda_client.invoke(FunctionName=lambda_name1, Payload=b"{}")
            result_data1 = result1["Payload"].read()

            result2 = lambda_client.invoke(FunctionName=lambda_name2, Payload=b"{}")
            result_data2 = result2["Payload"].read()

            assert 200 == result1["StatusCode"]
            assert "setting1" in to_str(result_data1)

            assert 200 == result2["StatusCode"]
            assert "setting2" in to_str(result_data2)

            # clean up
            lambda_client.delete_function(FunctionName=lambda_name1)
            lambda_client.delete_function(FunctionName=lambda_name2)
        finally:
            lambda_api.DO_USE_DOCKER = original_do_use_docker


class TestFunctionStates:
    @markers.aws.only_localstack
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
            localstack.services.lambda_.legacy.lambda_api,
            "do_set_function_code",
            _do_set_function_code,
        )
        try:
            response = aws_client.lambda_.create_function(
                FunctionName=function_name,
                Runtime="python3.9",
                Handler="handler.handler",
                Role=lambda_su_role,
                Code={"ZipFile": zip_file},
            )

            assert response["State"] == "Pending"

            with pytest.raises(ClientError) as e:
                aws_client.lambda_.invoke(FunctionName=function_name, Payload=b"{}")

            assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 409
            assert e.match("ResourceConflictException")
            assert e.match(
                "The operation cannot be performed at this time. The function is currently in the following state: Pending"
            )

            # let function move to active
            function_code_set.set()

            # lambda has to get active at some point
            def _check_lambda_state():
                response = aws_client.lambda_.get_function(FunctionName=function_name)
                assert response["Configuration"]["State"] == "Active"
                return response

            retry(_check_lambda_state)
            aws_client.lambda_.invoke(FunctionName=function_name, Payload=b"{}")
        finally:
            try:
                aws_client.lambda_.delete_function(FunctionName=function_name)
            except Exception:
                LOG.debug("Unable to delete function %s", function_name)
