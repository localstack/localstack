import boto3

from localstack.services.motoserver import MotoServer, get_moto_server
from localstack.utils.common import get_free_tcp_port


def test_get_moto_server_returns_singleton():
    assert get_moto_server() is get_moto_server()


def test_moto_server():
    # despite being a new instance, it actually shares state with the singleton (because moto runs in-memory)
    server = MotoServer(get_free_tcp_port())

    # test startup lifecycle
    assert not server.is_up()
    assert not server.is_running()
    server.start()
    assert server.wait_is_up(10)
    assert server.is_up()
    assert server.is_running()

    # test http calls are possible
    sns = boto3.client(
        "sns",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        aws_session_token="test",
        region_name="us-east-1",
        endpoint_url=server.url,
    )
    data = sns.list_topics()
    assert "Topics" in data

    # test shutdown lifecycle
    server.shutdown()
    server.join(10)
    assert not server.is_up()
    assert not server.is_running()
