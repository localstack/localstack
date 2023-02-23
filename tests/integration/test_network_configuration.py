"""
This test file captures the _current_ state of returning URLs before making
sweeping changes. This is to ensure that the refactoring does not cause
external breaking behaviour. In the future we can update this test suite to
correspond to the behaviour we want, and we get a todo list of things to
change 😂
"""
import pytest

from localstack import config, constants
from localstack.utils.strings import short_uid

# TODO: how do we test `localstack_hostname` - this variable configures the
# host that services make requests to when starting up (e.g. opensearch) and
# they won't start if we override the variable.


pytestmark = [pytest.mark.only_localstack]


@pytest.fixture
def patch_hostnames(monkeypatch):
    """
    Update both HOSTNAME_EXTERNAL and LOCALSTACK_HOSTNAME to custom values to configure the running localstack instance.
    """
    hostname_external = f"external-host-{short_uid()}"
    localstack_hostname = f"localstack-hostname={short_uid()}"
    monkeypatch.setattr(config, "HOSTNAME_EXTERNAL", hostname_external)
    # monkeypatch.setattr(config, "LOCALSTACK_HOSTNAME", localstack_hostname)
    yield hostname_external, localstack_hostname


class TestSQS:
    def test_off_strategy(self, monkeypatch, sqs_create_queue, patch_hostnames):
        external_port = "12345"

        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", "off")
        monkeypatch.setattr(config, "SQS_PORT_EXTERNAL", external_port)

        external_hostname, localstack_hostname = patch_hostnames

        queue_url = sqs_create_queue()

        assert external_hostname in queue_url

        assert localstack_hostname not in queue_url

    def test_domain_strategy(self, monkeypatch, sqs_create_queue, patch_hostnames):
        external_port = "12345"

        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", "domain")
        monkeypatch.setattr(config, "SQS_PORT_EXTERNAL", external_port)

        external_hostname, localstack_hostname = patch_hostnames
        queue_url = sqs_create_queue()

        assert constants.LOCALHOST_HOSTNAME in queue_url

        assert external_hostname not in queue_url
        assert localstack_hostname not in queue_url

    def test_path_strategy(self, monkeypatch, sqs_create_queue, patch_hostnames):
        external_port = "12345"

        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", "path")
        monkeypatch.setattr(config, "SQS_PORT_EXTERNAL", external_port)

        external_hostname, localstack_hostname = patch_hostnames
        queue_url = sqs_create_queue()

        assert "localhost" in queue_url

        assert constants.LOCALHOST_HOSTNAME not in queue_url
        assert external_hostname not in queue_url
        assert localstack_hostname not in queue_url


class TestOpenSearch:
    """
    OpenSearch does not respect any customisations and just returns a domain with localhost.localstack.cloud in.
    """

    def test_default_strategy(
        self, opensearch_client, opensearch_wait_for_cluster, patch_hostnames
    ):
        domain_name = f"domain-{short_uid()}"
        res = opensearch_client.create_domain(DomainName=domain_name)
        opensearch_wait_for_cluster(domain_name)
        endpoint = res["DomainStatus"]["Endpoint"]

        hostname_external, localstack_hostname = patch_hostnames

        assert constants.LOCALHOST_HOSTNAME in endpoint

        assert hostname_external not in endpoint
        assert localstack_hostname not in endpoint

    def test_port_strategy(
        self, monkeypatch, opensearch_client, opensearch_wait_for_cluster, patch_hostnames
    ):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "port")

        domain_name = f"domain-{short_uid()}"
        res = opensearch_client.create_domain(DomainName=domain_name)
        opensearch_wait_for_cluster(domain_name)
        endpoint = res["DomainStatus"]["Endpoint"]

        hostname_external, localstack_hostname = patch_hostnames

        assert "127.0.0.1" in endpoint

        assert hostname_external not in endpoint
        assert localstack_hostname not in endpoint
        assert constants.LOCALHOST_HOSTNAME not in endpoint

    def test_path_strategy(
        self, monkeypatch, opensearch_client, opensearch_wait_for_cluster, patch_hostnames
    ):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "path")

        domain_name = f"domain-{short_uid()}"
        res = opensearch_client.create_domain(DomainName=domain_name)
        opensearch_wait_for_cluster(domain_name)
        endpoint = res["DomainStatus"]["Endpoint"]

        hostname_external, localstack_hostname = patch_hostnames

        assert "localhost" in endpoint

        assert hostname_external not in endpoint
        assert localstack_hostname not in endpoint
        assert constants.LOCALHOST_HOSTNAME not in endpoint
