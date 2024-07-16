import gzip
import json
import logging
import os
import threading
from http.client import HTTPConnection
from urllib.parse import urlparse

import botocore.exceptions
import pytest
from opensearchpy import OpenSearch
from opensearchpy.exceptions import AuthorizationException

from localstack import config
from localstack.aws.api.opensearch import AdvancedSecurityOptionsInput, MasterUserOptions
from localstack.constants import (
    ELASTICSEARCH_DEFAULT_VERSION,
    OPENSEARCH_DEFAULT_VERSION,
    OPENSEARCH_PLUGIN_LIST,
)
from localstack.services.opensearch import provider
from localstack.services.opensearch.cluster import CustomEndpoint, EdgeProxiedOpensearchCluster
from localstack.services.opensearch.cluster_manager import (
    CustomBackendManager,
    DomainKey,
    MultiClusterManager,
    MultiplexingClusterManager,
    SingletonClusterManager,
    create_cluster_manager,
)
from localstack.services.opensearch.packages import opensearch_package
from localstack.testing.pytest import markers
from localstack.utils.common import call_safe, poll_condition, retry, short_uid, start_worker_thread
from localstack.utils.common import safe_requests as requests
from localstack.utils.strings import to_str
from localstack.utils.urls import localstack_host

LOG = logging.getLogger(__name__)

# Common headers used when sending requests to OpenSearch
COMMON_HEADERS = {"content-type": "application/json", "Accept-encoding": "identity"}

# Lock and event to ensure that the installation is executed before the tests
INIT_LOCK = threading.Lock()
installed = threading.Event()


def install_async():
    """
    Installs the default opensearch version in a worker thread. Used by conftest.py to make
    sure opensearch is downloaded once the tests arrive here.
    """
    if installed.is_set():
        return

    def run_install(*args):
        with INIT_LOCK:
            if installed.is_set():
                return
            LOG.info("installing opensearch default version")
            opensearch_package.install()
            LOG.info("done installing opensearch default version")
            installed.set()

    start_worker_thread(run_install)


@pytest.fixture(autouse=True)
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


@markers.skip_offline
class TestOpensearchProvider:
    """
    Because this test reuses the localstack instance for each test, all tests are performed with
    OPENSEARCH_MULTI_CLUSTER=True, regardless of changes in the config value.
    """

    @markers.aws.validated
    def test_list_versions(self, aws_client, snapshot):
        response = aws_client.opensearch.list_versions()
        versions = sorted(
            version
            for version in response["Versions"]
            # LocalStack does not support these versions
            if version not in ["Elasticsearch_1.5", "Elasticsearch_2.3"]
        )
        snapshot.match("versions", versions)

    @markers.aws.validated
    def test_get_compatible_versions(self, aws_client, snapshot):
        response = aws_client.opensearch.get_compatible_versions()
        source_versions = sorted(
            version["SourceVersion"] for version in response["CompatibleVersions"]
        )
        snapshot.match("source_versions", source_versions)
        for version in sorted(response["CompatibleVersions"], key=lambda x: x["SourceVersion"]):
            snapshot.match(f"source_{version['SourceVersion'].lower()}", version["TargetVersions"])

    @markers.aws.needs_fixing
    def test_get_compatible_version_for_domain(self, opensearch_create_domain, aws_client):
        opensearch_domain = opensearch_create_domain(EngineVersion=ELASTICSEARCH_DEFAULT_VERSION)
        response = aws_client.opensearch.get_compatible_versions(DomainName=opensearch_domain)
        assert "CompatibleVersions" in response
        compatible_versions = response["CompatibleVersions"]

        assert len(compatible_versions) == 1
        compatibility = compatible_versions[0]
        assert compatibility["SourceVersion"] == ELASTICSEARCH_DEFAULT_VERSION
        # Just check if 1.1 is contained (not equality) to avoid breaking the test if new versions are supported
        assert "OpenSearch_1.3" in compatibility["TargetVersions"]

    @markers.aws.needs_fixing
    def test_create_domain(self, opensearch_wait_for_cluster, aws_client):
        domain_name = f"opensearch-domain-{short_uid()}"
        try:
            domain_status = aws_client.opensearch.create_domain(DomainName=domain_name)[
                "DomainStatus"
            ]

            response = aws_client.opensearch.list_domain_names(EngineType="OpenSearch")
            domain_names = [domain["DomainName"] for domain in response["DomainNames"]]

            assert domain_name in domain_names
            # wait for the cluster
            opensearch_wait_for_cluster(domain_name=domain_name)

            # make sure the plugins are installed
            plugins_url = (
                f"https://{domain_status['Endpoint']}/_cat/plugins?s=component&h=component"
            )
            plugins_response = requests.get(plugins_url, headers={"Accept": "application/json"})
            installed_plugins = {plugin["component"] for plugin in plugins_response.json()}
            requested_plugins = set(OPENSEARCH_PLUGIN_LIST)
            assert requested_plugins.issubset(installed_plugins)
        finally:
            aws_client.opensearch.delete_domain(DomainName=domain_name)

    @markers.aws.only_localstack
    def test_security_plugin(self, opensearch_create_domain, aws_client):
        master_user_auth = ("master-user", "1[D3&2S)u9[G")

        # enable the security plugin for this test
        advanced_security_options = AdvancedSecurityOptionsInput(
            Enabled=True,
            InternalUserDatabaseEnabled=True,
            MasterUserOptions=MasterUserOptions(
                MasterUserName=master_user_auth[0],
                MasterUserPassword=master_user_auth[1],
            ),
        )
        domain_name = opensearch_create_domain(AdvancedSecurityOptions=advanced_security_options)
        endpoint = aws_client.opensearch.describe_domain(DomainName=domain_name)["DomainStatus"][
            "Endpoint"
        ]

        # make sure the plugins are installed
        plugins_url = f"https://{endpoint}/_cat/plugins?s=component&h=component"

        # request without credentials fails
        unauthorized_response = requests.get(plugins_url, headers={"Accept": "application/json"})
        assert unauthorized_response.status_code == 401

        # request with default admin credentials is successful
        plugins_response = requests.get(
            plugins_url, headers={"Accept": "application/json"}, auth=master_user_auth
        )
        assert plugins_response.status_code == 200
        installed_plugins = {plugin["component"] for plugin in plugins_response.json()}
        assert "opensearch-security" in installed_plugins

        # create a new index with the admin user
        test_index_name = "new-index"
        test_index_id = "new-index-id"
        test_document = {"test-key": "test-value"}
        admin_client = OpenSearch(hosts=endpoint, http_auth=master_user_auth)
        admin_client.create(test_index_name, id=test_index_id, body={})
        admin_client.index(test_index_name, body=test_document)

        # create a new "readall" rolemapping
        test_rolemapping = {"backend_roles": ["readall"], "users": []}
        response = requests.put(
            f"https://{endpoint}/_plugins/_security/api/rolesmapping/readall",
            json=test_rolemapping,
            auth=master_user_auth,
        )
        assert response.status_code == 201

        # create a new user which is only mapped to the readall role
        test_user_auth = ("test_user", "J2j7Gun!30Abvy")
        test_user = {"password": test_user_auth[1], "backend_roles": ["readall"]}
        response = requests.put(
            f"https://{endpoint}/_plugins/_security/api/internalusers/{test_user_auth[0]}",
            json=test_user,
            auth=master_user_auth,
        )
        assert response.status_code == 201

        # ensure the user can only read but cannot write
        test_user_client = OpenSearch(hosts=endpoint, http_auth=test_user_auth)

        def _search():
            search_result = test_user_client.search(
                index=test_index_name, body={"query": {"match": {"test-key": "value"}}}
            )
            assert "hits" in search_result
            assert search_result["hits"]["hits"][0]["_source"] == test_document

        # it might take a bit for the document to be indexed
        retry(_search, sleep=0.5, retries=3)

        with pytest.raises(AuthorizationException):
            test_user_client.create("new-index2", id="new-index-id2", body={})

        with pytest.raises(AuthorizationException):
            test_user_client.index(test_index_name, body={"test-key1": "test-value1"})

        # add the user to the all_access role
        rolemappins_patch = [{"op": "add", "path": "/users/-", "value": "test_user"}]
        response = requests.patch(
            f"https://{endpoint}/_plugins/_security/api/rolesmapping/all_access",
            json=rolemappins_patch,
            auth=master_user_auth,
        )
        assert response.status_code == 200

        # ensure the user can now write and create a new index
        test_user_client.create("new-index2", id="new-index-id2", body={})
        test_user_client.index(test_index_name, body={"test-key1": "test-value1"})

    @markers.aws.validated
    def test_create_domain_with_invalid_name(self, aws_client):
        with pytest.raises(botocore.exceptions.ClientError) as e:
            aws_client.opensearch.create_domain(
                DomainName="123abc"
            )  # domain needs to start with alphabetic characters
        assert e.value.response["Error"]["Code"] == "ValidationException"

        with pytest.raises(botocore.exceptions.ClientError) as e:
            aws_client.opensearch.create_domain(DomainName="abc#")  # no special characters allowed
        assert e.value.response["Error"]["Code"] == "ValidationException"

    @markers.aws.needs_fixing
    def test_create_domain_with_invalid_custom_endpoint(self, aws_client):
        with pytest.raises(botocore.exceptions.ClientError) as e:
            aws_client.opensearch.create_domain(
                DomainName="abc",
                DomainEndpointOptions={
                    "CustomEndpoint": "custom-endpoint",
                },
            )  # CustomEndpoint cannot be set without CustomEndpointEnabled
        assert e.value.response["Error"]["Code"] == "ValidationException"

        with pytest.raises(botocore.exceptions.ClientError) as e:
            aws_client.opensearch.create_domain(
                DomainName="abc",
                DomainEndpointOptions={
                    "CustomEndpointEnabled": True,
                },
            )  # CustomEndpointEnabled cannot be set without CustomEndpoint
        assert e.value.response["Error"]["Code"] == "ValidationException"

    @markers.aws.validated
    def test_exception_header_field(self, aws_client):
        """Test if the error response correctly sets the error code in the headers (see #6304)."""
        with pytest.raises(botocore.exceptions.ClientError) as e:
            # use an invalid domain name to provoke an exception
            aws_client.opensearch.create_domain(DomainName="123")
        assert (
            e.value.response["ResponseMetadata"]["HTTPHeaders"]["x-amzn-errortype"]
            == "ValidationException"
        )

    @markers.aws.needs_fixing
    def test_create_existing_domain_causes_exception(self, opensearch_wait_for_cluster, aws_client):
        domain_name = f"opensearch-domain-{short_uid()}"
        try:
            aws_client.opensearch.create_domain(DomainName=domain_name)
            with pytest.raises(botocore.exceptions.ClientError) as e:
                aws_client.opensearch.create_domain(DomainName=domain_name)
            assert e.value.response["Error"]["Code"] == "ResourceAlreadyExistsException"
            opensearch_wait_for_cluster(domain_name=domain_name)
        finally:
            aws_client.opensearch.delete_domain(DomainName=domain_name)

    @markers.aws.needs_fixing
    def test_describe_domains(self, opensearch_domain, aws_client):
        response = aws_client.opensearch.describe_domains(DomainNames=[opensearch_domain])
        assert len(response["DomainStatusList"]) == 1
        assert response["DomainStatusList"][0]["DomainName"] == opensearch_domain

    @markers.aws.needs_fixing
    def test_gzip_responses(self, opensearch_endpoint, monkeypatch):
        def send_plain_request(method, url):
            """
            It's basically impossible to send a request without an Accept-Encoding header with Python's standard
            lib when using http.client.
            This function sends a plain request by directly interacting with the HTTPConnection.
            """
            parsed = urlparse(url)
            connection = HTTPConnection(host=parsed.hostname, port=parsed.port)
            connection.putrequest(method, parsed.path, skip_accept_encoding=True)
            connection.endheaders()
            response = connection.getresponse()
            try:
                return response, response.read()
            finally:
                # make sure to close the connectio *after* we've called ``response.read()``.
                response.close()

        plain_response, data = send_plain_request("GET", opensearch_endpoint)
        assert plain_response.status == 200
        assert "cluster_name" in to_str(data)

        # ensure that requests with the "Accept-Encoding": "gzip" header receive gzip compressed responses
        gzip_accept_headers = {"Accept-Encoding": "gzip"}
        gzip_response = requests.get(opensearch_endpoint, headers=gzip_accept_headers, stream=True)
        # get the raw data, don't let requests decode the response
        raw_gzip_data = b"".join(
            chunk for chunk in gzip_response.raw.stream(1024, decode_content=False)
        )
        # force the gzip decoding here (which would raise an exception if it's not actually gzip)
        assert gzip.decompress(raw_gzip_data)

    @markers.aws.needs_fixing
    def test_domain_version(self, opensearch_domain, opensearch_create_domain, aws_client):
        response = aws_client.opensearch.describe_domain(DomainName=opensearch_domain)
        assert "DomainStatus" in response
        status = response["DomainStatus"]
        assert "EngineVersion" in status
        assert status["EngineVersion"] == OPENSEARCH_DEFAULT_VERSION

    @markers.aws.needs_fixing
    def test_update_domain_config(self, opensearch_domain, aws_client):
        initial_response = aws_client.opensearch.describe_domain_config(
            DomainName=opensearch_domain
        )
        update_response = aws_client.opensearch.update_domain_config(
            DomainName=opensearch_domain, ClusterConfig={"InstanceType": "r4.16xlarge.search"}
        )
        final_response = aws_client.opensearch.describe_domain_config(DomainName=opensearch_domain)

        assert (
            initial_response["DomainConfig"]["ClusterConfig"]["Options"]["InstanceType"]
            != update_response["DomainConfig"]["ClusterConfig"]["Options"]["InstanceType"]
        )
        assert (
            update_response["DomainConfig"]["ClusterConfig"]["Options"]["InstanceType"]
            == "r4.16xlarge.search"
        )
        assert (
            update_response["DomainConfig"]["ClusterConfig"]["Options"]["InstanceType"]
            == final_response["DomainConfig"]["ClusterConfig"]["Options"]["InstanceType"]
        )

    @markers.aws.needs_fixing
    def test_create_indices(self, opensearch_endpoint):
        indices = ["index1", "index2"]
        for index_name in indices:
            index_path = f"{opensearch_endpoint}/{index_name}"
            requests.put(index_path, headers=COMMON_HEADERS)
            endpoint = f"{opensearch_endpoint}/_cat/indices/{index_name}?format=json&pretty"
            req = requests.get(endpoint)
            assert req.status_code == 200
            req_result = json.loads(req.text)
            assert req_result[0]["health"] in ["green", "yellow"]
            assert req_result[0]["index"] in indices

        # create a knn index to make sure the knn plugin works
        index_path = f"{opensearch_endpoint}/knn"
        body = {
            "settings": {"index": {"knn": True}},
            "mappings": {
                "properties": {
                    "embedding": {
                        "type": "knn_vector",
                        "dimension": 2,
                    }
                }
            },
        }
        put = requests.put(index_path, headers=COMMON_HEADERS, json=body)
        assert put.status_code == 200
        get = requests.get(f"{opensearch_endpoint}/_cat/indices/knn?format=json&pretty")
        assert get.status_code == 200

        # add a document
        document_path = f"{opensearch_endpoint}/knn/_doc/test_document"
        body = {"embedding": [1, 2]}
        put = requests.put(document_path, headers=COMMON_HEADERS, json=body)
        assert put.status_code == 201

        get = requests.get(document_path)
        assert get.status_code == 200

    @markers.aws.needs_fixing
    def test_get_document(self, opensearch_document_path):
        response = requests.get(opensearch_document_path)
        assert (
            "I'm just a simple man" in response.text
        ), f"document not found({response.status_code}): {response.text}"

    @markers.aws.needs_fixing
    def test_search(self, opensearch_endpoint, opensearch_document_path):
        index = "/".join(opensearch_document_path.split("/")[:-2])
        # force the refresh of the index after the document was added, so it can appear in search
        response = requests.post(f"{opensearch_endpoint}/_refresh", headers=COMMON_HEADERS)
        assert response.ok

        search = {"query": {"match": {"last_name": "Fett"}}}
        response = requests.get(f"{index}/_search", data=json.dumps(search), headers=COMMON_HEADERS)

        assert (
            "I'm just a simple man" in response.text
        ), f"search unsuccessful({response.status_code}): {response.text}"

    @markers.aws.only_localstack
    def test_endpoint_strategy_path(self, monkeypatch, opensearch_create_domain, aws_client):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "path")

        domain_name = f"opensearch-domain-{short_uid()}"

        opensearch_create_domain(DomainName=domain_name)
        status = aws_client.opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]

        assert "Endpoint" in status
        endpoint = status["Endpoint"]
        assert endpoint.endswith(f"/{domain_name}")

    @markers.aws.only_localstack
    def test_endpoint_strategy_port(self, monkeypatch, opensearch_create_domain, aws_client):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "port")

        domain_name = f"opensearch-domain-{short_uid()}"

        opensearch_create_domain(DomainName=domain_name)
        status = aws_client.opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]

        assert "Endpoint" in status
        endpoint = status["Endpoint"]
        parts = endpoint.split(":")
        assert parts[0] in (localstack_host().host, "127.0.0.1")
        assert int(parts[1]) in range(
            config.EXTERNAL_SERVICE_PORTS_START, config.EXTERNAL_SERVICE_PORTS_END
        )

    # testing CloudFormation deployment here to make sure OpenSearch is installed
    @markers.aws.needs_fixing
    def test_cloudformation_deployment(self, deploy_cfn_template, aws_client):
        domain_name = f"domain-{short_uid()}"
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/opensearch_domain.yaml"
            ),
            parameters={"OpenSearchDomainName": domain_name},
        )

        response = aws_client.opensearch.list_domain_names(EngineType="OpenSearch")
        domain_names = [domain["DomainName"] for domain in response["DomainNames"]]
        assert domain_name in domain_names


@markers.skip_offline
class TestEdgeProxiedOpensearchCluster:
    @markers.aws.only_localstack
    def test_route_through_edge(self):
        cluster_id = f"domain-{short_uid()}"
        cluster_url = f"{config.internal_service_url()}/{cluster_id}"
        arn = f"arn:aws:es:us-east-1:000000000000:domain/{cluster_id}"
        cluster = EdgeProxiedOpensearchCluster(cluster_url, arn, CustomEndpoint(True, cluster_url))

        try:
            cluster.start()
            assert cluster.wait_is_up(240), "gave up waiting for server"

            response = requests.get(cluster_url)
            assert response.ok, f"cluster endpoint returned an error: {response.text}"
            assert response.json()["version"]["number"] == "2.11.1"

            response = requests.get(f"{cluster_url}/_cluster/health")
            assert response.ok, f"cluster health endpoint returned an error: {response.text}"
            assert response.json()["status"] in [
                "red",
                "orange",
                "yellow",
                "green",
            ], "expected cluster state to be in a valid state"

        finally:
            cluster.shutdown()

        assert poll_condition(
            lambda: not cluster.is_up(), timeout=240
        ), "gave up waiting for cluster to shut down"

    @markers.aws.only_localstack
    def test_custom_endpoint(
        self, opensearch_wait_for_cluster, opensearch_create_domain, aws_client
    ):
        domain_name = f"opensearch-domain-{short_uid()}"
        custom_endpoint = "http://localhost:4566/my-custom-endpoint"
        domain_endpoint_options = {
            "CustomEndpoint": custom_endpoint,
            "CustomEndpointEnabled": True,
        }

        opensearch_create_domain(
            DomainName=domain_name, DomainEndpointOptions=domain_endpoint_options
        )

        response = aws_client.opensearch.describe_domain(DomainName=domain_name)
        response_domain_endpoint_options = response["DomainStatus"]["DomainEndpointOptions"]
        assert response_domain_endpoint_options["EnforceHTTPS"] is False
        assert response_domain_endpoint_options["TLSSecurityPolicy"]
        assert response_domain_endpoint_options["CustomEndpointEnabled"] is True
        assert response_domain_endpoint_options["CustomEndpoint"] == custom_endpoint

        response = aws_client.opensearch.list_domain_names(EngineType="OpenSearch")
        domain_names = [domain["DomainName"] for domain in response["DomainNames"]]

        assert domain_name in domain_names
        # wait for the cluster
        opensearch_wait_for_cluster(domain_name=domain_name)
        response = requests.get(f"{custom_endpoint}/_cluster/health")
        assert response.ok
        assert response.status_code == 200

    @markers.aws.only_localstack
    def test_custom_endpoint_disabled(
        self, opensearch_wait_for_cluster, opensearch_create_domain, aws_client
    ):
        domain_name = f"opensearch-domain-{short_uid()}"
        domain_endpoint_options = {
            "CustomEndpointEnabled": False,
        }

        opensearch_create_domain(
            DomainName=domain_name, DomainEndpointOptions=domain_endpoint_options
        )

        response = aws_client.opensearch.describe_domain(DomainName=domain_name)
        response_domain_name = response["DomainStatus"]["DomainName"]
        assert domain_name == response_domain_name

        response_domain_endpoint_options = response["DomainStatus"]["DomainEndpointOptions"]
        assert response_domain_endpoint_options["EnforceHTTPS"] is False
        assert response_domain_endpoint_options["TLSSecurityPolicy"]
        assert response_domain_endpoint_options["CustomEndpointEnabled"] is False
        assert "CustomEndpoint" not in response_domain_endpoint_options

        endpoint = f"http://{response['DomainStatus']['Endpoint']}"

        # wait for the cluster
        opensearch_wait_for_cluster(domain_name=domain_name)
        response = requests.get(f"{endpoint}/_cluster/health")
        assert response.ok
        assert response.status_code == 200


@markers.skip_offline
class TestMultiClusterManager:
    @markers.aws.only_localstack
    def test_multi_cluster(self, account_id, monkeypatch):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "domain")
        monkeypatch.setattr(config, "OPENSEARCH_MULTI_CLUSTER", True)

        manager = MultiClusterManager()

        # create two opensearch domains
        domain_key_0 = DomainKey(
            domain_name=f"domain-{short_uid()}",
            region="us-east-1",
            account=account_id,
        )
        domain_key_1 = DomainKey(
            domain_name=f"domain-{short_uid()}",
            region="us-east-1",
            account=account_id,
        )
        cluster_0 = manager.create(domain_key_0.arn, OPENSEARCH_DEFAULT_VERSION)
        cluster_1 = manager.create(domain_key_1.arn, OPENSEARCH_DEFAULT_VERSION)

        try:
            # spawn the two clusters
            assert cluster_0.wait_is_up(240)
            assert cluster_1.wait_is_up(240)

            retry(lambda: try_cluster_health(cluster_0.url), retries=12, sleep=10)
            retry(lambda: try_cluster_health(cluster_1.url), retries=12, sleep=10)

            # create an index in cluster_0, wait for it to appear, make sure it's not in cluster_1
            index_url_0 = cluster_0.url + "/my-index?pretty"
            index_url_1 = cluster_1.url + "/my-index?pretty"

            response = requests.put(index_url_0)
            assert response.ok, f"failed to put index into cluster {cluster_0.url}: {response.text}"
            assert poll_condition(
                lambda: requests.head(index_url_0).ok, timeout=10
            ), "gave up waiting for index"

            assert not requests.head(index_url_1).ok, "index should not appear in second cluster"

        finally:
            call_safe(cluster_0.shutdown)
            call_safe(cluster_1.shutdown)


@markers.skip_offline
class TestMultiplexingClusterManager:
    @markers.aws.only_localstack
    def test_multiplexing_cluster(self, account_id, monkeypatch):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "domain")
        monkeypatch.setattr(config, "OPENSEARCH_MULTI_CLUSTER", False)

        manager = MultiplexingClusterManager()

        # create two opensearch domains
        domain_key_0 = DomainKey(
            domain_name=f"domain-{short_uid()}",
            region="us-east-1",
            account=account_id,
        )
        domain_key_1 = DomainKey(
            domain_name=f"domain-{short_uid()}",
            region="us-east-1",
            account=account_id,
        )
        cluster_0 = manager.create(domain_key_0.arn, OPENSEARCH_DEFAULT_VERSION)
        cluster_1 = manager.create(domain_key_1.arn, OPENSEARCH_DEFAULT_VERSION)

        try:
            # spawn the two clusters
            assert cluster_0.wait_is_up(240)
            assert cluster_1.wait_is_up(240)

            retry(lambda: try_cluster_health(cluster_0.url), retries=12, sleep=10)
            retry(lambda: try_cluster_health(cluster_1.url), retries=12, sleep=10)

            # create an index in cluster_0, wait for it to appear, make sure it's in cluster_1, too
            index_url_0 = cluster_0.url + "/my-index?pretty"
            index_url_1 = cluster_1.url + "/my-index?pretty"

            response = requests.put(index_url_0)
            assert response.ok, f"failed to put index into cluster {cluster_0.url}: {response.text}"
            assert poll_condition(
                lambda: requests.head(index_url_0).ok, timeout=10
            ), "gave up waiting for index"

            assert requests.head(index_url_1).ok, "index should appear in second cluster"

        finally:
            call_safe(cluster_0.shutdown)
            call_safe(cluster_1.shutdown)


@markers.skip_offline
class TestSingletonClusterManager:
    @markers.aws.only_localstack
    def test_endpoint_strategy_port_singleton_cluster(self, account_id, monkeypatch):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "port")
        monkeypatch.setattr(config, "OPENSEARCH_MULTI_CLUSTER", False)

        manager = SingletonClusterManager()

        # create two opensearch domains
        domain_key_0 = DomainKey(
            domain_name=f"domain-{short_uid()}",
            region="us-east-1",
            account=account_id,
        )
        domain_key_1 = DomainKey(
            domain_name=f"domain-{short_uid()}",
            region="us-east-1",
            account=account_id,
        )
        cluster_0 = manager.create(domain_key_0.arn, OPENSEARCH_DEFAULT_VERSION)
        cluster_1 = manager.create(domain_key_1.arn, OPENSEARCH_DEFAULT_VERSION)

        # check if the first port url matches the port range

        parts = cluster_0.url.split(":")
        assert parts[0] == "http"
        # either f"//{the bind host}" is used, or in the case of "//0.0.0.0" the localstack hostname instead
        assert parts[1][2:] in [config.GATEWAY_LISTEN[0].host, localstack_host().host]
        assert int(parts[2]) in range(
            config.EXTERNAL_SERVICE_PORTS_START, config.EXTERNAL_SERVICE_PORTS_END
        )

        # check if the second url matches the first one
        assert cluster_0.url == cluster_1.url

        try:
            # wait for the two clusters
            assert cluster_0.wait_is_up(240)
            # make sure cluster_0 (which is equal to cluster_1) is reachable
            retry(lambda: try_cluster_health(cluster_0.url), retries=3, sleep=5)
        finally:
            call_safe(cluster_0.shutdown)
            call_safe(cluster_1.shutdown)


@markers.skip_offline
class TestCustomBackendManager:
    @markers.aws.only_localstack
    def test_custom_backend(self, account_id, httpserver, monkeypatch):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "domain")
        monkeypatch.setattr(config, "OPENSEARCH_CUSTOM_BACKEND", httpserver.url_for("/"))

        # create fake elasticsearch cluster
        httpserver.expect_request("/").respond_with_json(
            {
                "name": "om",
                "cluster_name": "opensearch",
                "cluster_uuid": "gREewvVZR0mIswR-8-6VRQ",
                "version": {
                    "number": "7.10.0",
                    "build_flavor": "default",
                    "build_type": "tar",
                    "build_hash": "51e9d6f22758d0374a0f3f5c6e8f3a7997850f96",
                    "build_date": "2020-11-09T21:30:33.964949Z",
                    "build_snapshot": False,
                    "lucene_version": "8.7.0",
                    "minimum_wire_compatibility_version": "6.8.0",
                    "minimum_index_compatibility_version": "6.0.0-beta1",
                },
                "tagline": "You Know, for Search",
            }
        )
        httpserver.expect_request("/_cluster/health").respond_with_json(
            {
                "cluster_name": "opensearch",
                "status": "green",
                "timed_out": False,
                "number_of_nodes": 1,
                "number_of_data_nodes": 1,
                "active_primary_shards": 0,
                "active_shards": 0,
                "relocating_shards": 0,
                "initializing_shards": 0,
                "unassigned_shards": 0,
                "delayed_unassigned_shards": 0,
                "number_of_pending_tasks": 0,
                "number_of_in_flight_fetch": 0,
                "task_max_waiting_in_queue_millis": 0,
                "active_shards_percent_as_number": 100,
            }
        )

        manager = create_cluster_manager()
        assert isinstance(manager, CustomBackendManager)

        domain_key = DomainKey(
            domain_name=f"domain-{short_uid()}",
            region="us-east-1",
            account=account_id,
        )
        cluster = manager.create(domain_key.arn, OPENSEARCH_DEFAULT_VERSION)
        # check that we're using the domain endpoint strategy
        assert f"{domain_key.domain_name}." in cluster.url

        try:
            assert cluster.wait_is_up(10)
            retry(lambda: try_cluster_health(cluster.url), retries=3, sleep=5)

        finally:
            call_safe(cluster.shutdown)

        httpserver.check()

    @markers.aws.only_localstack
    def test_custom_backend_with_custom_endpoint(
        self,
        httpserver,
        monkeypatch,
        opensearch_wait_for_cluster,
        opensearch_create_domain,
        aws_client,
    ):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "domain")
        monkeypatch.setattr(config, "OPENSEARCH_CUSTOM_BACKEND", httpserver.url_for("/"))
        # reset the singleton for the test
        monkeypatch.setattr(provider, "__CLUSTER_MANAGER", None)

        # create fake elasticsearch cluster
        custom_name = "my_very_special_custom_backend"
        httpserver.expect_request("/").respond_with_json(
            {
                "name": custom_name,
                "status": "green",
            }
        )
        httpserver.expect_request("/_cluster/health").respond_with_json(
            {
                "name_health": custom_name,
                "status": "green",
            }
        )
        domain_name = f"opensearch-domain-{short_uid()}"
        custom_endpoint = "http://localhost:4566/my-custom-endpoint"
        domain_endpoint_options = {
            "CustomEndpoint": custom_endpoint,
            "CustomEndpointEnabled": True,
        }
        opensearch_create_domain(
            DomainName=domain_name, DomainEndpointOptions=domain_endpoint_options
        )
        response = aws_client.opensearch.list_domain_names(EngineType="OpenSearch")
        domain_names = [domain["DomainName"] for domain in response["DomainNames"]]

        assert domain_name in domain_names

        opensearch_wait_for_cluster(domain_name=domain_name)

        response = requests.get(f"{custom_endpoint}/")
        assert response.ok
        assert custom_name in response.text
        response = requests.get(f"{custom_endpoint}/_cluster/health")
        assert response.ok
        assert custom_name in response.text
