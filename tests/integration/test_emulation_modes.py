from localstack import config
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


class TestEmulationModes:
    def test_emulation_mode_mock(self, monkeypatch, opensearch_client):
        monkeypatch.setattr(config, "EMULATION_MODE", "mock")

        name_prefix = f"dom-{short_uid()}"
        # assume that creating 100 clusters can only work in mocked mode ...
        num_clusters = 100
        domains = []

        try:
            for i in range(num_clusters):
                dom_name = f"{name_prefix}-{i}"
                opensearch_client.create_domain(DomainName=dom_name)
                domains.append(dom_name)

            def _check_statuses():
                for i in range(num_clusters):
                    dom_name = f"{name_prefix}-{i}"
                    response = opensearch_client.describe_domain(DomainName=dom_name)
                    processing = response["DomainStatus"].get("Processing")
                    assert processing is False  # Processing=False indicates that cluster is ready

            retry(_check_statuses)
        finally:
            for domain in domains:
                opensearch_client.delete_domain(DomainName=domain)
