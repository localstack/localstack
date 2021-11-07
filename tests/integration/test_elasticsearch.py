import json
import logging
import threading
import time
import unittest

import pytest
from botocore.exceptions import ClientError

from localstack import config
from localstack.constants import ELASTICSEARCH_DEFAULT_VERSION, TEST_AWS_ACCOUNT_ID
from localstack.services.es.cluster import EdgeProxiedElasticsearchCluster
from localstack.services.es.cluster_manager import MultiClusterManager, MultiplexingClusterManager
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
TEST_DOMAIN_NAME = "test_es_domain_1"
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


class ElasticsearchTest(unittest.TestCase):
    @classmethod
    def init_async(cls):
        install_async()

    @classmethod
    def setUpClass(cls):
        # this is the configuration the test was originally written for
        config.ES_ENDPOINT_STRATEGY = "off"
        config.ES_MULTI_CLUSTER = False

        then = time.time()
        LOG.info("waiting for initialization lock")
        with INIT_LOCK:
            LOG.info("initialization lock acquired in %.2f seconds", time.time() - then)

            cls.es_url = aws_stack.get_local_service_url("elasticsearch")
            # create ES domain
            cls._create_domain(name=TEST_DOMAIN_NAME)
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
        es_client = aws_stack.connect_to_service("es")
        es_client.delete_elasticsearch_domain(DomainName=TEST_DOMAIN_NAME)
        assert TEST_DOMAIN_NAME not in [
            d["DomainName"] for d in es_client.list_domain_names()["DomainNames"]
        ]

    def test_create_existing_domain_causes_exception(self):
        # the domain was already created in TEST_DOMAIN_NAME
        with self.assertRaises(ClientError):
            self._create_domain(name=TEST_DOMAIN_NAME, es_cluster_config=ES_CLUSTER_CONFIG)

    def test_domain_es_version(self):
        es_client = aws_stack.connect_to_service("es")

        status = es_client.describe_elasticsearch_domain(DomainName=TEST_DOMAIN_NAME)[
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
            endpoint = "http://localhost:{}/_cat/indices/{}?format=json&pretty".format(
                config.PORT_ELASTICSEARCH, index_name
            )
            req = requests.get(endpoint)
            self.assertEqual(200, req.status_code)
            req_result = json.loads(req.text)
            self.assertIn(req_result[0]["health"], ["green", "yellow"])
            self.assertIn(req_result[0]["index"], indexes)

        es_client = aws_stack.connect_to_service("es")
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
        self.assertTrue(status_test_domain_name_1["DomainStatus"]["Created"])
        self.assertTrue(status_test_domain_name_2["DomainStatus"]["Created"])

    def test_domain_creation(self):
        es_client = aws_stack.connect_to_service("es")

        # make sure we cannot re-create same domain name
        self.assertRaises(
            ClientError,
            es_client.create_elasticsearch_domain,
            DomainName=TEST_DOMAIN_NAME,
        )

        # get domain status
        status = es_client.describe_elasticsearch_domain(DomainName=TEST_DOMAIN_NAME)
        self.assertEqual(TEST_DOMAIN_NAME, status["DomainStatus"]["DomainName"])
        self.assertTrue(status["DomainStatus"]["Created"])
        self.assertFalse(status["DomainStatus"]["Processing"])
        self.assertFalse(status["DomainStatus"]["Deleted"])
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
    def _add_document(self, id, document):
        article_path = "{}/{}/employee/{}?pretty".format(self.es_url, TEST_INDEX, id)
        resp = requests.put(article_path, data=json.dumps(document), headers=COMMON_HEADERS)
        # Pause to allow the document to be indexed
        time.sleep(1)
        return resp

    @classmethod
    def _delete_document(self, id):
        article_path = "{}/{}/employee/{}?pretty".format(self.es_url, TEST_INDEX, id)
        resp = requests.delete(article_path, headers=COMMON_HEADERS)
        # Pause to allow the document to be indexed
        time.sleep(1)
        return resp

    @classmethod
    def _create_domain(cls, name=None, version=None, es_cluster_config=None):
        es_client = aws_stack.connect_to_service("es")
        name = name or TEST_DOMAIN_NAME
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
            created = status["DomainStatus"]["Created"]
            LOG.info("asserting created state of domain %s (state = %s)", name, created)
            assert created, "gave up waiting on cluster to be ready"

        retry(check_cluster_ready, sleep=10, retries=12)


class TestEdgeProxiedElasticsearchCluster:
    def test_route_through_edge(self):
        cluster_id = f"domain-{short_uid()}"
        cluster_url = f"http://localhost:4566/{cluster_id}"
        cluster = EdgeProxiedElasticsearchCluster(cluster_url)

        try:
            with INIT_LOCK:
                cluster.start()
                assert cluster.wait_is_up(120), "gave up waiting for server"

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
            lambda: not cluster.is_up(), timeout=10
        ), "gave up waiting for cluster to shut down"


class TestMultiClusterManager:
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
            cluster0.wait_is_up(120)
            cluster1.wait_is_up(120)

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


class TestMultiplexingClusterManager:
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
            cluster0.wait_is_up(120)
            cluster1.wait_is_up(120)

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
