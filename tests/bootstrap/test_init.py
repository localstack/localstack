import textwrap

from localstack.testing.pytest.container import ContainerFactory
from localstack.utils.bootstrap import ContainerConfigurators, get_gateway_url
from localstack.utils.container_utils.container_client import VolumeBind


def test_init_scripts_executor(
    container_factory: ContainerFactory,
    wait_for_localstack_ready,
    stream_container_logs,
    aws_client_factory,
    tmp_path,
):
    ready_script_sh = textwrap.dedent("""#!/bin/bash
        awslocal sqs create-queue --queue-name test-sqs-queue
        """)
    ready_script_sh_path = tmp_path / "create-queue.sh"
    ready_script_sh_path.write_text(ready_script_sh)
    ready_script_sh_path.chmod(0o777)

    start_script_py = "import os; print('creating folder'); os.mkdir('/tmp/foobar')"
    start_script_py_path = tmp_path / "create_folder.py"
    start_script_py_path.write_text(start_script_py)

    ls_container = container_factory(
        configurators=[
            # we need the default port for awslocal to work out of the box
            ContainerConfigurators.default_gateway_port,
            ContainerConfigurators.random_container_name,
            ContainerConfigurators.volume(
                VolumeBind(
                    str(start_script_py_path), "/etc/localstack/init/start.d/create_folder.py"
                ),
            ),
            ContainerConfigurators.volume(
                VolumeBind(
                    str(ready_script_sh_path), "/etc/localstack/init/ready.d/create-queue.sh"
                ),
            ),
        ]
    )

    running_container = ls_container.start()
    stream_container_logs(ls_container)
    wait_for_localstack_ready(running_container)
    url = get_gateway_url(ls_container)

    # start script run correctly
    out, err = running_container.exec_in_container(command=["stat", "/tmp/foobar"])
    assert b"File: /tmp/foobar" in out

    # ready script run correctly
    client = aws_client_factory(endpoint_url=url)
    result = client.sqs.list_queues()
    assert result["QueueUrls"]
    assert "test-sqs-queue" in result["QueueUrls"][0]
