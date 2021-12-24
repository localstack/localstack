import pytest

from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services.es.cluster_manager import DomainKey, build_cluster_endpoint


class TestBuildClusterEndpoint:
    def test_endpoint_strategy_off(self, monkeypatch):
        monkeypatch.setattr(config, "ES_ENDPOINT_STRATEGY", "off")
        endpoint = build_cluster_endpoint(DomainKey("my-domain", "us-east-1", TEST_AWS_ACCOUNT_ID))
        assert endpoint == "localhost:4571"

    @pytest.mark.skipif(
        condition=config.in_docker(), reason="port mapping differs when being run in the container"
    )
    def test_endpoint_strategy_path(self, monkeypatch):
        monkeypatch.setattr(config, "ES_ENDPOINT_STRATEGY", "path")

        endpoint = build_cluster_endpoint(DomainKey("my-domain", "us-east-1", TEST_AWS_ACCOUNT_ID))
        assert endpoint == "localhost:4566/es/us-east-1/my-domain"

        endpoint = build_cluster_endpoint(
            DomainKey("my-domain-1", "eu-central-1", TEST_AWS_ACCOUNT_ID)
        )
        assert endpoint == "localhost:4566/es/eu-central-1/my-domain-1"

    @pytest.mark.skipif(
        condition=config.in_docker(), reason="port mapping differs when being run in the container"
    )
    def test_endpoint_strategy_domain(self, monkeypatch):
        monkeypatch.setattr(config, "ES_ENDPOINT_STRATEGY", "domain")

        endpoint = build_cluster_endpoint(DomainKey("my-domain", "us-east-1", TEST_AWS_ACCOUNT_ID))
        assert endpoint == "my-domain.us-east-1.es.localhost.localstack.cloud:4566"

        endpoint = build_cluster_endpoint(
            DomainKey("my-domain-1", "eu-central-1", TEST_AWS_ACCOUNT_ID)
        )
        assert endpoint == "my-domain-1.eu-central-1.es.localhost.localstack.cloud:4566"


class TestDomainKey:
    def test_from_arn(self):
        domain_key = DomainKey.from_arn("arn:aws:es:us-east-1:012345678901:domain/my-es-domain")

        assert domain_key.domain_name == "my-es-domain"
        assert domain_key.region == "us-east-1"
        assert domain_key.account == "012345678901"

    def test_arn(self):
        domain_key = DomainKey(
            domain_name="my-es-domain",
            region="us-east-1",
            account="012345678901",
        )

        assert domain_key.arn == "arn:aws:es:us-east-1:012345678901:domain/my-es-domain"

    def test_from_arn_wrong_service(self):
        with pytest.raises(ValueError):
            DomainKey.from_arn("arn:aws:sqs:us-east-1:012345678901:my-queue")
