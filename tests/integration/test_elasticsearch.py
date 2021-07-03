import json
import logging
import time
import unittest

from botocore.exceptions import ClientError

from localstack import config
from localstack.services.es.es_api import DEFAULT_ES_VERSION
from localstack.utils.aws import aws_stack
from localstack.utils.common import retry
from localstack.utils.common import safe_requests as requests
from localstack.utils.common import short_uid

LOG = logging.getLogger(__name__)

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


class ElasticsearchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
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
        assert resp.status_code == 201, "Request failed({}): {}".format(resp.status_code, resp.text)

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
        # already created in
        with self.assertRaises(ClientError):
            self._create_domain(name=TEST_DOMAIN_NAME, es_cluster_config=ES_CLUSTER_CONFIG)

    def test_domain_es_version(self):
        es_client = aws_stack.connect_to_service("es")

        status = es_client.describe_elasticsearch_domain(DomainName=TEST_DOMAIN_NAME)[
            "DomainStatus"
        ]
        self.assertEqual(DEFAULT_ES_VERSION, status["ElasticsearchVersion"])

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
            "http://localhost:%s" % config.PORT_ELASTICSEARCH,
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
            assert created

        retry(check_cluster_ready, sleep=10, retries=12)
