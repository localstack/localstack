import json
import logging
import threading

import pytest

from localstack.constants import OPENSEARCH_DEFAULT_VERSION
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

    def test_domain_version(self, opensearch_client, opensearch_domain, opensearch_create_domain):
        response = opensearch_client.describe_domain(DomainName=opensearch_domain)
        assert "DomainStatus" in response
        status = response["DomainStatus"]
        assert "EngineVersion" in status
        assert status["EngineVersion"] == f"OpenSearch_{OPENSEARCH_DEFAULT_VERSION}"

        # FIXME can't create second domain. always `ResourceAlreadyExistsException`
        domain_name = opensearch_create_domain(EngineVersion="OpenSearch_1.0")
        response = opensearch_client.describe_domain(DomainName=domain_name)
        assert "DomainStatus" in response
        status = response["DomainStatus"]
        assert "EngineVersion" in status
        assert status["EngineVersion"] == "OpenSearch_1.0"

    def test_create_indices(self, opensearch_url):
        indices = ["index1", "index2"]
        for index_name in indices:
            index_path = f"{opensearch_url}/{index_name}"
            requests.put(index_path, headers=COMMON_HEADERS)
            endpoint = f"{opensearch_url}/_cat/indices/{index_name}?format=json&pretty"
            req = requests.get(endpoint)
            assert req.status_code == 200
            req_result = json.loads(req.text)
            assert req_result[0]["health"] in ["green", "yellow"]
            assert req_result[0]["index"] in indices

    def test_get_document(self, opensearch_document_path):
        response = requests.get(opensearch_document_path)
        assert (
            "I'm just a simple man" in response.text
        ), f"document not found({response.status_code}): {response.text}"

    def test_search(self, opensearch_url, opensearch_document_path):
        index = "/".join(opensearch_document_path.split("/")[:-1])
        search = {"query": {"match": {"last_name": "Fett"}}}
        # FIXME doesn't find Boba Fett
        response = requests.get(f"{index}/_search", data=json.dumps(search), headers=COMMON_HEADERS)

        assert (
            "I'm just a simple man" in response.text
        ), f"search unsuccessful({response.status_code}): {response.text}"
