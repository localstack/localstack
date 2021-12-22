import json
import logging
import threading
import time
import unittest

import pytest
from botocore.exceptions import ClientError

from localstack import config
from localstack.constants import ELASTICSEARCH_DEFAULT_VERSION, TEST_AWS_ACCOUNT_ID
from localstack.services.es import es_api
from localstack.services.es.cluster import EdgeProxiedElasticsearchCluster
from localstack.services.es.cluster_manager import (
    CustomBackendManager,
    MultiClusterManager,
    MultiplexingClusterManager,
    SingletonClusterManager,
    create_cluster_manager,
)
from localstack.services.es.es_api import get_domain_arn
from localstack.services.install import install_elasticsearch
from localstack.utils.aws import aws_stack
from localstack.utils.common import call_safe, poll_condition, retry
from localstack.utils.common import safe_requests as requests
from localstack.utils.common import short_uid, start_worker_thread

LOG = logging.getLogger(__name__)
INIT_LOCK = threading.Lock()

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

installed = threading.Event()


def install_async():
    """
    Installs the default elasticsearch version in a worker thread. Used by conftest.py to make
    sure elasticsearch is downloaded once the tests arrive here.
    """
    if installed.is_set():
        return

    def run_install(*args):
        with INIT_LOCK:
            if installed.is_set():
                return

            LOG.info("installing elasticsearch")
            install_elasticsearch()
            LOG.info("done installing elasticsearch")
            installed.set()

    start_worker_thread(run_install)


@pytest.fixture(autouse=True)
def elasticsearch():
    if not installed.is_set():
        install_async()

    # wait up to five minutes for the installation to finish
    assert installed.wait(timeout=60 * 5), "gave up waiting for elasticsearch to install"
    yield


def try_cluster_health(cluster_url: str):
    response = requests.get(cluster_url)
    assert response.ok, "cluster endpoint returned an error: %s" % response.text

    response = requests.get(f"{cluster_url}/_cluster/health")
    assert response.ok, "cluster health endpoint returned an error: %s" % response.text
    assert response.json()["status"] in [
        "orange",
        "yellow",
        "green",
    ], "expected cluster state to be in a valid state"


class ElasticsearchTest(unittest.TestCase):
    # TODO: refactor this test into a pytest

    domain_name: str

    @classmethod
    def init_async(cls):
        install_async()

    @classmethod
    def setUpClass(cls):
        # this is the configuration the test was originally written for
        config.ES_ENDPOINT_STRATEGY = "off"
        config.ES_MULTI_CLUSTER = False

        # FIXME clean up this test to avoid these hacks!
        es_api.cluster_manager().shutdown_all()
        es_api._cluster_manager = None
        manager = es_api.cluster_manager()
        assert isinstance(manager, SingletonClusterManager)

        then = time.time()
        LOG.info("waiting for initialization lock")
        with INIT_LOCK:
            LOG.info("initialization lock acquired in %.2f seconds", time.time() - then)

            cls.es_url = aws_stack.get_local_service_url("elasticsearch")
            # create ES domain
            cls.domain_name = f"test-domain-{short_uid()}"
            cls._create_domain(name=cls.domain_name)

            document = {
                "first_name": "Jane",
                "last_name": "Smith",
                "age": 32,
                "about": "I like to collect rock albums",
                "interests": ["music"],
            }
            resp = cls._add_document(TEST_DOC_ID, document)
            assert resp.status_code == 201, "Request failed({}): {}".format(
                resp.status_code, resp.text
            )

    @classmethod
    def tearDownClass(cls):
        cls._delete_document(TEST_DOC_ID)

        # make sure domain deletion works
        es_client = aws_stack.create_external_boto_client("es")
        es_client.delete_elasticsearch_domain(DomainName=cls.domain_name)
        assert cls.domain_name not in [
            d["DomainName"] for d in es_client.list_domain_names()["DomainNames"]
        ]

        es_api.cluster_manager().shutdown_all()
        es_api._cluster_manager = None

    def test_create_existing_domain_causes_exception(self):
        # the domain was already created in TEST_DOMAIN_NAME
        with self.assertRaises(ClientError):
            self._create_domain(name=self.domain_name, es_cluster_config=ES_CLUSTER_CONFIG)

    def test_describe_elasticsearch_domains(self):
        es_client = aws_stack.create_external_boto_client("es")

        result = es_client.describe_elasticsearch_domains(DomainNames=[self.domain_name])
        self.assertEqual(1, len(result["DomainStatusList"]))
        self.assertEqual(result["DomainStatusList"][0]["DomainName"], self.domain_name)

    def test_domain_es_version(self):
        es_client = aws_stack.create_external_boto_client("es")

        status = es_client.describe_elasticsearch_domain(DomainName=self.domain_name)[
            "DomainStatus"
        ]
        self.assertEqual(ELASTICSEARCH_DEFAULT_VERSION, status["ElasticsearchVersion"])

        domain_name = "es-%s" % short_uid()
        self._create_domain(name=domain_name, version="6.8", es_cluster_config=ES_CLUSTER_CONFIG)
        status = es_client.describe_elasticsearch_domain(DomainName=domain_name)["DomainStatus"]
        self.assertEqual("6.8", status["ElasticsearchVersion"])
        self.assertEqual(ES_CLUSTER_CONFIG, status["ElasticsearchClusterConfig"])

    def test_create_indexes_and_domains(self):
        indexes = ["index1", "index2"]
        for index_name in indexes:
            index_path = "{}/{}".format(self.es_url, index_name)
            requests.put(index_path, headers=COMMON_HEADERS)
            endpoint = "{}/_cat/indices/{}?format=json&pretty".format(self.es_url, index_name)
            req = requests.get(endpoint)
            self.assertEqual(200, req.status_code)
            req_result = json.loads(req.text)
            self.assertIn(req_result[0]["health"], ["green", "yellow"])
            self.assertIn(req_result[0]["index"], indexes)

        es_client = aws_stack.create_external_boto_client("es")
        test_domain_name_1 = "test1-%s" % short_uid()
        test_domain_name_2 = "test2-%s" % short_uid()
        self._create_domain(name=test_domain_name_1, version="6.8")
        self._create_domain(name=test_domain_name_2, version="6.8")
        status_test_domain_name_1 = es_client.describe_elasticsearch_domain(
            DomainName=test_domain_name_1
        )
        status_test_domain_name_2 = es_client.describe_elasticsearch_domain(
            DomainName=test_domain_name_2
        )
        self.assertFalse(status_test_domain_name_1["DomainStatus"]["Processing"])
        self.assertFalse(status_test_domain_name_2["DomainStatus"]["Processing"])

    def test_domain_creation(self):
        es_client = aws_stack.create_external_boto_client("es")

        # make sure we cannot re-create same domain name
        self.assertRaises(
            ClientError,
            es_client.create_elasticsearch_domain,
            DomainName=self.domain_name,
        )

        # get domain status
        status = es_client.describe_elasticsearch_domain(DomainName=self.domain_name)
        self.assertEqual(self.domain_name, status["DomainStatus"]["DomainName"])
        self.assertTrue(status["DomainStatus"]["Created"])
        self.assertFalse(status["DomainStatus"]["Deleted"])

        # wait for domain to appear
        self.assertTrue(
            poll_condition(lambda: status["DomainStatus"].get("Processing") is False, timeout=30)
        )
        self.assertEqual(
            "localhost:%s" % config.PORT_ELASTICSEARCH,
            status["DomainStatus"]["Endpoint"],
        )
        self.assertTrue(status["DomainStatus"]["EBSOptions"]["EBSEnabled"])

        # make sure we can fake adding tags to a domain
        response = es_client.add_tags(
            ARN="string", TagList=[{"Key": "SOME_TAG", "Value": "SOME_VALUE"}]
        )
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

    def test_elasticsearch_get_document(self):
        article_path = "{}/{}/employee/{}?pretty".format(self.es_url, TEST_INDEX, TEST_DOC_ID)
        resp = requests.get(article_path, headers=COMMON_HEADERS)

        self.assertIn(
            "I like to collect rock albums",
            resp.text,
            msg="Document not found({}): {}".format(resp.status_code, resp.text),
        )

    def test_elasticsearch_search(self):
        search_path = "{}/{}/employee/_search?pretty".format(self.es_url, TEST_INDEX)

        search = {"query": {"match": {"last_name": "Smith"}}}

        resp = requests.get(search_path, data=json.dumps(search), headers=COMMON_HEADERS)

        self.assertIn(
            "I like to collect rock albums",
            resp.text,
            msg="Search failed({}): {}".format(resp.status_code, resp.text),
        )

    @classmethod
    def _add_document(cls, id, document):
        article_path = "{}/{}/employee/{}?pretty".format(cls.es_url, TEST_INDEX, id)
        resp = requests.put(article_path, data=json.dumps(document), headers=COMMON_HEADERS)
        # Pause to allow the document to be indexed
        time.sleep(1)
        return resp

    @classmethod
    def _delete_document(cls, id):
        article_path = "{}/{}/employee/{}?pretty".format(cls.es_url, TEST_INDEX, id)
        resp = requests.delete(article_path, headers=COMMON_HEADERS)
        # Pause to allow the document to be indexed
        time.sleep(1)
        return resp

    @classmethod
    def _create_domain(cls, name=None, version=None, es_cluster_config=None):
        es_client = aws_stack.create_external_boto_client("es")
        name = name or cls.domain_name
        kwargs = {}
        if version:
            kwargs["ElasticsearchVersion"] = version
        if es_cluster_config:
            kwargs["ElasticsearchClusterConfig"] = es_cluster_config
        LOG.info("creating elasticsearch domain %s", name)
        es_client.create_elasticsearch_domain(DomainName=name, **kwargs)
        assert name in [d["DomainName"] for d in es_client.list_domain_names()["DomainNames"]]

        # wait for completion status
        def check_cluster_ready(*args):
            status = es_client.describe_elasticsearch_domain(DomainName=name)
            processing = status["DomainStatus"]["Processing"]
            LOG.info(
                "asserting that cluster of domain %s is not processing (processing = %s)",
                name,
                processing,
            )
            assert processing is False, "gave up waiting on cluster to be ready"

            # also check that the cluster is healthy
            try_cluster_health(f"http://{status['DomainStatus']['Endpoint']}")

        retry(check_cluster_ready, sleep=10, retries=24)


class TestEdgeProxiedElasticsearchCluster:
    def test_route_through_edge(self):
        cluster_id = f"domain-{short_uid()}"
        cluster_url = f"http://localhost:{config.EDGE_PORT}/{cluster_id}"
        cluster = EdgeProxiedElasticsearchCluster(cluster_url)

        try:
            cluster.start()
            assert cluster.wait_is_up(240), "gave up waiting for server"

            response = requests.get(cluster_url)
            assert response.ok, "cluster endpoint returned an error: %s" % response.text
            assert response.json()["version"]["number"] == cluster.version

            response = requests.get(f"{cluster_url}/_cluster/health")
            assert response.ok, "cluster health endpoint returned an error: %s" % response.text
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


class TestMultiClusterManager:
    @pytest.mark.skip_offline
    def test_multi_cluster(self, monkeypatch):
        monkeypatch.setattr(config, "ES_ENDPOINT_STRATEGY", "domain")
        monkeypatch.setattr(config, "ES_MULTI_CLUSTER", True)

        manager = MultiClusterManager()

        # create two elasticsearch domains
        domain0_name = f"domain-{short_uid()}"
        domain1_name = f"domain-{short_uid()}"
        domain0_arn = get_domain_arn(domain0_name, "us-east-1", TEST_AWS_ACCOUNT_ID)
        domain1_arn = get_domain_arn(domain1_name, "us-east-1", TEST_AWS_ACCOUNT_ID)
        cluster0 = manager.create(domain0_arn, dict(DomainName=domain0_name))
        cluster1 = manager.create(domain1_arn, dict(DomainName=domain1_name))

        try:
            # spawn the two clusters
            assert cluster0.wait_is_up(240)
            assert cluster1.wait_is_up(240)

            retry(lambda: try_cluster_health(cluster0.url), retries=12, sleep=10)
            retry(lambda: try_cluster_health(cluster1.url), retries=12, sleep=10)

            # create an index in cluster0, wait for it to appear, make sure it's not in cluster1
            index0_url = cluster0.url + "/my-index?pretty"
            index1_url = cluster1.url + "/my-index?pretty"

            response = requests.put(index0_url)
            assert response.ok, "failed to put index into cluster %s: %s" % (
                cluster0.url,
                response.text,
            )
            assert poll_condition(
                lambda: requests.head(index0_url).ok, timeout=10
            ), "gave up waiting for index"

            assert not requests.head(index1_url).ok, "index should not appear in second cluster"

        finally:
            call_safe(cluster0.shutdown)
            call_safe(cluster1.shutdown)


class TestElasticsearchApi:
    def test_list_es_versions(self, es_client):
        response = es_client.list_elasticsearch_versions()

        assert "ElasticsearchVersions" in response

        versions = response["ElasticsearchVersions"]
        assert "7.10" in versions
        assert "5.5" in versions

    def test_get_compatible_versions(self, es_client):
        response = es_client.get_compatible_elasticsearch_versions()

        assert "CompatibleElasticsearchVersions" in response

        versions = response["CompatibleElasticsearchVersions"]
        assert {"SourceVersion": "5.5", "TargetVersions": ["5.6"]} in versions


class TestMultiplexingClusterManager:
    @pytest.mark.skip_offline
    def test_multiplexing_cluster(self, monkeypatch):
        monkeypatch.setattr(config, "ES_ENDPOINT_STRATEGY", "domain")
        monkeypatch.setattr(config, "ES_MULTI_CLUSTER", False)

        manager = MultiplexingClusterManager()

        # create two elasticsearch domains
        domain0_name = f"domain-{short_uid()}"
        domain1_name = f"domain-{short_uid()}"
        domain0_arn = get_domain_arn(domain0_name, "us-east-1", TEST_AWS_ACCOUNT_ID)
        domain1_arn = get_domain_arn(domain1_name, "us-east-1", TEST_AWS_ACCOUNT_ID)
        cluster0 = manager.create(domain0_arn, dict(DomainName=domain0_name))
        cluster1 = manager.create(domain1_arn, dict(DomainName=domain1_name))

        try:
            # spawn the two clusters
            assert cluster0.wait_is_up(240)
            assert cluster1.wait_is_up(240)

            retry(lambda: try_cluster_health(cluster0.url), retries=12, sleep=10)
            retry(lambda: try_cluster_health(cluster1.url), retries=12, sleep=10)

            # create an index in cluster0, wait for it to appear, make sure it's not in cluster1
            index0_url = cluster0.url + "/my-index?pretty"
            index1_url = cluster1.url + "/my-index?pretty"

            response = requests.put(index0_url)
            assert response.ok, "failed to put index into cluster %s: %s" % (
                cluster0.url,
                response.text,
            )
            assert poll_condition(
                lambda: requests.head(index0_url).ok, timeout=10
            ), "gave up waiting for index"

            assert requests.head(index1_url).ok, "expected index to appear by multiplexing"

        finally:
            call_safe(cluster0.shutdown)
            call_safe(cluster1.shutdown)


class TestCustomBackendManager:
    def test_custom_backend(self, httpserver, monkeypatch):
        monkeypatch.setattr(config, "ES_ENDPOINT_STRATEGY", "domain")
        monkeypatch.setattr(config, "ES_CUSTOM_BACKEND", httpserver.url_for("/"))

        # create fake elasticsearch cluster
        httpserver.expect_request("/").respond_with_json(
            {
                "name": "om",
                "cluster_name": "elasticsearch",
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
                "cluster_name": "elasticsearch",
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

        domain_name = f"domain-{short_uid()}"
        cluster_arn = get_domain_arn(domain_name)

        cluster = manager.create(cluster_arn, dict(DomainName=domain_name))
        # check that we're using the domain endpoint strategy
        assert f"{domain_name}." in cluster.url

        try:
            assert cluster.wait_is_up(10)
            retry(lambda: try_cluster_health(cluster.url), retries=3, sleep=5)

        finally:
            call_safe(cluster.shutdown)

        httpserver.check()
