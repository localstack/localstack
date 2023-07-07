import json
import os
import time

import pytest

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.lambda_utils import is_old_provider
from localstack.utils.container_networking import get_main_container_network
from localstack.utils.docker_utils import DOCKER_CLIENT, get_host_path_for_path_in_docker
from localstack.utils.files import load_file, mkdir, rm_rf
from localstack.utils.strings import short_uid, to_str
from localstack.utils.sync import retry
from localstack.utils.testutil import create_lambda_archive
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_ENV, THIS_FOLDER

HOT_RELOADING_NODEJS_HANDLER = os.path.join(
    THIS_FOLDER, "functions/hot-reloading/nodejs/handler.mjs"
)
HOT_RELOADING_PYTHON_HANDLER = os.path.join(
    THIS_FOLDER, "functions/hot-reloading/python/handler.py"
)
LAMBDA_NETWORKS_PYTHON_HANDLER = os.path.join(THIS_FOLDER, "functions/lambda_networks.py")


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
        runtime,
        handler_file,
        handler_filename,
        lambda_su_role,
        cleanups,
        aws_client,
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
        response = aws_client.awslambda.invoke(FunctionName=function_name, Payload=b"{}")
        response_dict = json.loads(response["Payload"].read())
        assert response_dict["counter"] == 1
        assert response_dict["constant"] == "value1"
        response = aws_client.awslambda.invoke(FunctionName=function_name, Payload=b"{}")
        response_dict = json.loads(response["Payload"].read())
        assert response_dict["counter"] == 2
        assert response_dict["constant"] == "value1"
        with open(os.path.join(hot_reloading_dir_path, handler_filename), mode="wt") as f:
            f.write(function_content.replace("value1", "value2"))
        # we have to sleep here, since the hot reloading is debounced with 500ms
        time.sleep(0.6)
        response = aws_client.awslambda.invoke(FunctionName=function_name, Payload=b"{}")
        response_dict = json.loads(response["Payload"].read())
        assert response_dict["counter"] == 1
        assert response_dict["constant"] == "value2"
        response = aws_client.awslambda.invoke(FunctionName=function_name, Payload=b"{}")
        response_dict = json.loads(response["Payload"].read())
        assert response_dict["counter"] == 2
        assert response_dict["constant"] == "value2"

        # test subdirs
        test_folder = os.path.join(hot_reloading_dir_path, "test-folder")
        mkdir(test_folder)
        # make sure the creation of the folder triggered reload
        time.sleep(0.6)
        response = aws_client.awslambda.invoke(FunctionName=function_name, Payload=b"{}")
        response_dict = json.loads(response["Payload"].read())
        assert response_dict["counter"] == 1
        assert response_dict["constant"] == "value2"
        # now writing something in the new folder to check if it will reload
        with open(os.path.join(test_folder, "test-file"), mode="wt") as f:
            f.write("test-content")
        time.sleep(0.6)
        response = aws_client.awslambda.invoke(FunctionName=function_name, Payload=b"{}")
        response_dict = json.loads(response["Payload"].read())
        assert response_dict["counter"] == 1
        assert response_dict["constant"] == "value2"

    def test_hot_reloading_publish_version(
        self, create_lambda_function_aws, lambda_su_role, cleanups, aws_client
    ):
        """
        Test if publish version code sha256s are ignored when using hot-reload (cannot be matched anyways)
        Serverless, for example, will hash the code before publishing on the client side, which can brick the publish
        version operation
        """

        function_name = f"test-hot-reloading-{short_uid()}"
        hot_reloading_bucket = config.BUCKET_MARKER_LOCAL
        tmp_path = config.dirs.tmp
        hot_reloading_dir_path = os.path.join(tmp_path, f"hot-reload-{short_uid()}")
        mkdir(hot_reloading_dir_path)
        cleanups.append(lambda: rm_rf(hot_reloading_dir_path))
        function_content = load_file(HOT_RELOADING_NODEJS_HANDLER)
        with open(os.path.join(hot_reloading_dir_path, "handler.mjs"), mode="wt") as f:
            f.write(function_content)

        mount_path = get_host_path_for_path_in_docker(hot_reloading_dir_path)
        create_lambda_function_aws(
            FunctionName=function_name,
            Handler="handler.handler",
            Code={"S3Bucket": hot_reloading_bucket, "S3Key": mount_path},
            Role=lambda_su_role,
            Runtime=Runtime.nodejs18_x,
        )
        aws_client.awslambda.publish_version(FunctionName=function_name, CodeSha256="zipfilehash")


@pytest.mark.skipif(condition=is_old_provider(), reason="Focussing on the new provider")
class TestDockerFlags:
    def test_additional_docker_flags(self, create_lambda_function, monkeypatch, aws_client):
        env_value = short_uid()
        monkeypatch.setattr(config, "LAMBDA_DOCKER_FLAGS", f"-e Hello={env_value}")
        function_name = f"test-flags-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_ENV,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        aws_client.awslambda.get_waiter("function_active_v2").wait(FunctionName=function_name)
        result = aws_client.awslambda.invoke(FunctionName=function_name, Payload="{}")
        result_data = result["Payload"].read()
        result_data = json.loads(to_str(result_data))
        assert {"Hello": env_value} == result_data

    def test_lambda_docker_networks(self, lambda_su_role, monkeypatch, aws_client, cleanups):
        function_name = f"test-network-{short_uid()}"
        container_name = f"server-{short_uid()}"
        additional_network = f"test-network-{short_uid()}"

        # networking setup
        main_network = get_main_container_network()
        DOCKER_CLIENT.create_network(additional_network)

        def _delete_network():
            retry(lambda: DOCKER_CLIENT.delete_network(additional_network))

        cleanups.append(_delete_network)
        DOCKER_CLIENT.run_container(
            image_name="nginx",
            remove=True,
            detach=True,
            name=container_name,
            network=additional_network,
        )
        cleanups.append(lambda: DOCKER_CLIENT.stop_container(container_name=container_name))
        monkeypatch.setattr(config, "LAMBDA_DOCKER_NETWORK", f"{main_network},{additional_network}")

        # we need to create a lambda manually here for the right cleanup order
        # (we need to destroy the function before the network, not the other way around. This is only guaranteed
        # with the cleanups fixture)
        zip_file = create_lambda_archive(
            load_file(LAMBDA_NETWORKS_PYTHON_HANDLER),
            get_content=True,
            runtime=Runtime.python3_9,
        )
        aws_client.awslambda.create_function(
            FunctionName=function_name,
            Code={"ZipFile": zip_file},
            Handler="handler.handler",
            Runtime=Runtime.python3_9,
            Role=lambda_su_role,
        )
        cleanups.append(lambda: aws_client.awslambda.delete_function(FunctionName=function_name))

        aws_client.awslambda.get_waiter("function_active_v2").wait(FunctionName=function_name)
        result = aws_client.awslambda.invoke(
            FunctionName=function_name, Payload=json.dumps({"url": f"http://{container_name}"})
        )
        result_data = result["Payload"].read()
        result_data = json.loads(to_str(result_data))
        assert result_data["status"] == 200
        assert "nginx" in result_data["response"]
