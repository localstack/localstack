import json
import logging
import threading

import pytest

from localstack.services.install import install_opensearch
from localstack.utils.common import safe_requests as requests
from localstack.utils.common import short_uid, start_worker_thread

LOG = logging.getLogger(__name__)

TEST_INDEX = "megacorp"
TEST_DOC_ID = 1
COMMON_HEADERS = {"content-type": "application/json", "Accept-encoding": "identity"}
ES_CLUSTER_CONFIG = {
    "InstanceType": "m3.xlarge.elasticsearch",
    "InstanceCount": 4,
    "DedicatedMasterEnabled": True,
    "ZoneAwarenessEnabled": True,
    "DedicatedMasterType": "m3.xlarge.elasticsearch",
    "DedicatedMasterCount": 3,
}

INIT_LOCK = threading.Lock()
installed = threading.Event()


def install_async():
    """
    Installs the default opensearch version in a worker thread. Used by conftest.py to make
    sure elasticsearch is downloaded once the tests arrive here.
    """

    if installed.is_set():
        return

    def run_install():
        with INIT_LOCK:
            if installed.is_set():
                return
            LOG.info("installing opensearch")
            install_opensearch()
            LOG.info("done installing opensearch")
            installed.set()

    start_worker_thread(run_install)


# FIXME: installed is never set (maybe doesn't work when already installed?)
@pytest.fixture(autouse=False)
def opensearch():
    if not installed.is_set():
        install_async()

    assert installed.wait(timeout=5 * 60), "gave up waiting for opensearch to install"
    yield


def try_cluster_health(cluster_url: str):
    response = requests.get(cluster_url)
    assert response.ok, f"cluster endpoint returned an error: {response.text}"

    response = requests.get(f"{cluster_url}/_cluster/health")
    assert response.ok, f"cluster health endpoint returned an error: {response.text}"
    assert response.json()["status"] in [
        "orange",
        "yellow",
        "green",
    ], "expected cluster state to be in a valid state"


class TestOpenSearchProvider:
    def test_list_versions(self, opensearch_client):
        response = opensearch_client.list_versions()

        assert "Versions" in response

        versions = response["Versions"]
        print(versions)

        assert "OpenSearch_1.0" in versions
        assert "OpenSearch_1.2" in versions

    def test_get_compatible_versions(self, opensearch_client):
        response = opensearch_client.get_compatible_versions()

        assert "CompatibleVersions" in response

        versions = response["CompatibleVersions"]

        # TODO in later iterations this should check for ElasticSearch compatibility
        assert len(versions) == 0

    # FIXME
    def test_create_domain(self, opensearch_client):
        domain_name = f"opensearch-domain-{short_uid()}"
        opensearch_client.create_domain(DomainName=domain_name)

        response = opensearch_client.list_domain_names(EngineType="OpenSearch")
        domain_names = [domain["DomainName"] for domain in response["DomainNames"]]

        assert domain_name in domain_names

    def test_create_existing_domain_causes_exception(self, opensearch_client):
        domain_name = f"opensearch-domain-{short_uid()}"
        opensearch_client.create_domain(DomainName=domain_name)
        opensearch_client.create_domain(DomainName=domain_name)

    def test_describe_domains(self, opensearch_client, opensearch_domain):
        response = opensearch_client.describe_domains(DomainNames=[opensearch_domain])
        assert len(response["DomainStatusList"]) == 1
        assert response["DomainStatusList"][0]["DomainName"] == opensearch_domain

    # FIXME
    def test_domain_version(self, opensearch_client, opensearch_domain):
        response = opensearch_client.describe_domains(DomainNames=[opensearch_domain])
        assert "DomainStatus" in response

    # TODO: domain creation as fixture?
    def test_create_indices_and_domains(self, opensearch_client):
        indices = ["index1", "index2"]
        for index_name in indices:
            # FIXME find that URL for opensearch
            index_path = "{}/{}".format(self.es_url, index_name)
            requests.put(index_path, headers=COMMON_HEADERS)
            endpoint = "{}/_cat/indices/{}?format=json&pretty".format(self.es_url, index_name)
            req = requests.get(endpoint)
            assert req.status_code == 200
            req_result = json.loads(req.text)
            assert req_result[0]["health"] in ["green", "yellow"]
            assert req_result[0]["index"] in indices

        test_domain_name_1 = f"opensearch-test1-{short_uid()}"
        test_domain_name_2 = f"opensearch-test2-{short_uid()}"
        opensearch_client.create_domain(DomainName=test_domain_name_1)
        opensearch_client.create_domain(DomainName=test_domain_name_2)
        status_test_domain_name_1 = opensearch_client.describe_domain(DomainName=test_domain_name_1)
        status_test_domain_name_2 = opensearch_client.describe_domain(DomainName=test_domain_name_2)
        assert status_test_domain_name_1["DomainStatus"]["Processing"] is False
        assert status_test_domain_name_2["DomainStatus"]["Processing"] is False

    # TODO needs document and domain fixture
    def test_get_document(self):
        pass

    # TODO needs document and domain fixture
    def test_search(self):
        pass
