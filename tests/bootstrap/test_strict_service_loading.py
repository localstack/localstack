import pytest
import requests
from botocore.exceptions import ClientError

from localstack.config import in_docker
from localstack.testing.pytest.container import ContainerFactory
from localstack.utils.bootstrap import ContainerConfigurators, get_gateway_url

pytestmarks = pytest.mark.skipif(
    condition=in_docker(), reason="cannot run bootstrap tests in docker"
)


def test_strict_service_loading(
    container_factory: ContainerFactory,
    wait_for_localstack_ready,
    aws_client_factory,
):
    ls_container = container_factory(
        configurators=[
            ContainerConfigurators.random_container_name,
            ContainerConfigurators.random_gateway_port,
            ContainerConfigurators.random_service_port_range(20),
            ContainerConfigurators.env_vars(
                {"STRICT_SERVICE_LOADING": "1", "SERVICES": "s3,sqs,sns"}
            ),
        ]
    )
    running_container = ls_container.start()
    wait_for_localstack_ready(running_container)
    url = get_gateway_url(ls_container)

    # check service-status returned by health endpoint
    response = requests.get(f"{url}/_localstack/health")
    assert response.ok

    services = response.json().get("services")

    assert services.pop("sqs") == "available"
    assert services.pop("s3") == "available"
    assert services.pop("sns") == "available"

    assert services
    assert all(services.get(key) == "disabled" for key in services.keys())

    # activate sqs service
    client = aws_client_factory(endpoint_url=url)
    result = client.sqs.list_queues()
    assert result

    # verify cloudwatch is not activated
    with pytest.raises(ClientError) as e:
        client.cloudwatch.list_metrics()

    e.match(
        "Service 'cloudwatch' is not enabled. Please check your 'SERVICES' configuration variable."
    )
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 501

    # check status again
    response = requests.get(f"{url}/_localstack/health")
    assert response.ok

    services = response.json().get("services")

    # sqs should be running now
    assert services.get("sqs") == "running"
    assert services.get("s3") == "available"
    assert services.get("sns") == "available"
    assert services.get("cloudwatch") == "disabled"
