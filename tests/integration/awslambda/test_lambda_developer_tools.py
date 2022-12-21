import json
import os
import time

import pytest

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.lambda_utils import is_old_provider
from localstack.utils.docker_utils import get_host_path_for_path_in_docker
from localstack.utils.files import load_file, mkdir, rm_rf
from localstack.utils.strings import short_uid, to_str
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_ENV, THIS_FOLDER

HOT_RELOADING_NODEJS_HANDLER = os.path.join(
    THIS_FOLDER, "functions/hot-reloading/nodejs/handler.mjs"
)
HOT_RELOADING_PYTHON_HANDLER = os.path.join(
    THIS_FOLDER, "functions/hot-reloading/python/handler.py"
)


@pytest.mark.skipif(condition=is_old_provider(), reason="Focussing on the new provider")
class TestHotReloading:
    @pytest.mark.parametrize(
        "runtime,handler_file,handler_filename",
        [
            (Runtime.nodejs18_x, HOT_RELOADING_NODEJS_HANDLER, "handler.mjs"),
            (Runtime.python3_9, HOT_RELOADING_PYTHON_HANDLER, "handler.py"),
        ],
        ids=["nodejs18.x", "python3.9"],
    )
    def test_hot_reloading(
        self,
        create_lambda_function_aws,
        lambda_client,
        runtime,
        handler_file,
        handler_filename,
        lambda_su_role,
        cleanups,
    ):
        """Test hot reloading of lambda code"""
        function_name = f"test-hot-reloading-{short_uid()}"
        hot_reloading_bucket = config.BUCKET_MARKER_LOCAL
        tmp_path = config.dirs.tmp
        hot_reloading_dir_path = os.path.join(tmp_path, f"hot-reload-{short_uid()}")
        mkdir(hot_reloading_dir_path)
        cleanups.append(lambda: rm_rf(hot_reloading_dir_path))
        function_content = load_file(handler_file)
        with open(os.path.join(hot_reloading_dir_path, handler_filename), mode="wt") as f:
            f.write(function_content)

        mount_path = get_host_path_for_path_in_docker(hot_reloading_dir_path)
        create_lambda_function_aws(
            FunctionName=function_name,
            Handler="handler.handler",
            Code={"S3Bucket": hot_reloading_bucket, "S3Key": mount_path},
            Role=lambda_su_role,
            Runtime=runtime,
        )
        response = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        response_dict = json.loads(response["Payload"].read())
        assert response_dict["counter"] == 1
        assert response_dict["constant"] == "value1"
        response = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        response_dict = json.loads(response["Payload"].read())
        assert response_dict["counter"] == 2
        assert response_dict["constant"] == "value1"
        with open(os.path.join(hot_reloading_dir_path, handler_filename), mode="wt") as f:
            f.write(function_content.replace("value1", "value2"))
        # we have to sleep here, since the hot reloading is debounced with 500ms
        time.sleep(0.6)
        response = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        response_dict = json.loads(response["Payload"].read())
        assert response_dict["counter"] == 1
        assert response_dict["constant"] == "value2"
        response = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        response_dict = json.loads(response["Payload"].read())
        assert response_dict["counter"] == 2
        assert response_dict["constant"] == "value2"

        # test subdirs
        test_folder = os.path.join(hot_reloading_dir_path, "test-folder")
        mkdir(test_folder)
        # make sure the creation of the folder triggered reload
        time.sleep(0.6)
        response = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        response_dict = json.loads(response["Payload"].read())
        assert response_dict["counter"] == 1
        assert response_dict["constant"] == "value2"
        # now writing something in the new folder to check if it will reload
        with open(os.path.join(test_folder, "test-file"), mode="wt") as f:
            f.write("test-content")
        time.sleep(0.6)
        response = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        response_dict = json.loads(response["Payload"].read())
        assert response_dict["counter"] == 1
        assert response_dict["constant"] == "value2"


@pytest.mark.skipif(condition=is_old_provider(), reason="Focussing on the new provider")
class TestDockerFlags:
    def test_additional_docker_flags(self, lambda_client, create_lambda_function, monkeypatch):
        env_value = short_uid()
        monkeypatch.setattr(config, "LAMBDA_DOCKER_FLAGS", f"-e Hello={env_value}")
        function_name = f"test-flags-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_ENV,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        lambda_client.get_waiter("function_active_v2").wait(FunctionName=function_name)
        result = lambda_client.invoke(FunctionName=function_name, Payload="{}")
        result_data = result["Payload"].read()
        result_data = json.loads(to_str(result_data))
        assert {"Hello": env_value} == result_data
