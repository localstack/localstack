import pytest

from localstack import config
from localstack.aws.api.opensearch import EngineType
from localstack.services.opensearch.cluster_manager import DomainKey, build_cluster_endpoint
from localstack.testing.config import TEST_AWS_ACCOUNT_ID


class TestBuildClusterEndpoint:
    def test_endpoint_strategy_port(self, monkeypatch):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "port")
        endpoint = build_cluster_endpoint(DomainKey("my-domain", "us-east-1", TEST_AWS_ACCOUNT_ID))
        parts = endpoint.split(":")
        assert parts[0] == "localhost.localstack.cloud"
        assert int(parts[1]) in range(
            config.EXTERNAL_SERVICE_PORTS_START, config.EXTERNAL_SERVICE_PORTS_END
        )

    @pytest.mark.skipif(
        condition=config.in_docker(), reason="port mapping differs when being run in the container"
    )
    @pytest.mark.parametrize(
        "engine", [(EngineType.OpenSearch, "opensearch"), (EngineType.Elasticsearch, "es")]
    )
    def test_endpoint_strategy_path(self, monkeypatch, engine):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "path")
        engine_type = engine[0]
        engine_path_prefix = engine[1]

        endpoint = build_cluster_endpoint(
            DomainKey("my-domain", "us-east-1", TEST_AWS_ACCOUNT_ID), engine_type=engine_type
        )
        assert (
            endpoint == f"localhost.localstack.cloud:4566/{engine_path_prefix}/us-east-1/my-domain"
        )

        endpoint = build_cluster_endpoint(
            DomainKey("my-domain-1", "eu-central-1", TEST_AWS_ACCOUNT_ID), engine_type=engine_type
        )
        assert (
            endpoint
            == f"localhost.localstack.cloud:4566/{engine_path_prefix}/eu-central-1/my-domain-1"
        )

    @pytest.mark.skipif(
        condition=config.in_docker(), reason="port mapping differs when being run in the container"
    )
    @pytest.mark.parametrize(
        "engine", [(EngineType.OpenSearch, "opensearch"), (EngineType.Elasticsearch, "es")]
    )
    def test_endpoint_strategy_domain(self, monkeypatch, engine):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "domain")
        engine_type = engine[0]
        engine_path_prefix = engine[1]

        endpoint = build_cluster_endpoint(
            domain_key=DomainKey("my-domain", "us-east-1", TEST_AWS_ACCOUNT_ID),
            engine_type=engine_type,
        )
        assert (
            endpoint == f"my-domain.us-east-1.{engine_path_prefix}.localhost.localstack.cloud:4566"
        )

        endpoint = build_cluster_endpoint(
            domain_key=DomainKey("my-domain-1", "eu-central-1", TEST_AWS_ACCOUNT_ID),
            engine_type=engine_type,
        )
        assert (
            endpoint
            == f"my-domain-1.eu-central-1.{engine_path_prefix}.localhost.localstack.cloud:4566"
        )


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
