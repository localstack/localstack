import json
import time
import unittest
from nose.tools import assert_equal, assert_in, assert_not_in
from botocore.exceptions import ClientError
from localstack import config
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid, retry, safe_requests as requests
from localstack.services.es.es_api import DEFAULT_ES_VERSION

TEST_INDEX = 'megacorp'
TEST_DOC_ID = 1
COMMON_HEADERS = {
    'content-type': 'application/json',
    'Accept-encoding': 'identity'
}
TEST_DOMAIN_NAME = 'test_es_domain_1'
TEST_ENDPOINT_URL = 'http://localhost:4571'


class ElasticsearchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.es_url = aws_stack.get_local_service_url('elasticsearch')
        # create ES domain
        cls._create_domain()
        document = {
            'first_name': 'Jane',
            'last_name': 'Smith',
            'age': 32,
            'about': 'I like to collect rock albums',
            'interests': ['music']
        }
        resp = cls._add_document(TEST_DOC_ID, document)
        assert_equal(resp.status_code, 201, msg='Request failed({}): {}'.format(resp.status_code, resp.text))

    @classmethod
    def tearDownClass(cls):
        cls._delete_document(TEST_DOC_ID)

        # make sure domain deletion works
        es_client = aws_stack.connect_to_service('es')
        es_client.delete_elasticsearch_domain(DomainName=TEST_DOMAIN_NAME)
        assert_not_in(TEST_DOMAIN_NAME, [d['DomainName'] for d in es_client.list_domain_names()['DomainNames']])

    def test_domain_es_version(self):
        es_client = aws_stack.connect_to_service('es')

        status = es_client.describe_elasticsearch_domain(DomainName=TEST_DOMAIN_NAME)['DomainStatus']
        self.assertEqual(status['ElasticsearchVersion'], DEFAULT_ES_VERSION)

        domain_name = 'es-%s' % short_uid()
        self._create_domain(name=domain_name, version='6.8')
        status = es_client.describe_elasticsearch_domain(DomainName=domain_name)['DomainStatus']
        self.assertEqual(status['ElasticsearchVersion'], '6.8')

    def test_domain_creation(self):
        es_client = aws_stack.connect_to_service('es')

        # make sure we cannot re-create same domain name
        self.assertRaises(ClientError, es_client.create_elasticsearch_domain, DomainName=TEST_DOMAIN_NAME)

        # get domain status
        status = es_client.describe_elasticsearch_domain(DomainName=TEST_DOMAIN_NAME)
        self.assertEqual(status['DomainStatus']['DomainName'], TEST_DOMAIN_NAME)
        self.assertTrue(status['DomainStatus']['Created'])
        self.assertFalse(status['DomainStatus']['Processing'])
        self.assertFalse(status['DomainStatus']['Deleted'])
        self.assertEqual(status['DomainStatus']['Endpoint'], 'http://localhost:%s' % config.PORT_ELASTICSEARCH)
        self.assertTrue(status['DomainStatus']['EBSOptions']['EBSEnabled'])

        # make sure we can fake adding tags to a domain
        response = es_client.add_tags(ARN='string', TagList=[{'Key': 'SOME_TAG', 'Value': 'SOME_VALUE'}])
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

    def test_elasticsearch_get_document(self):
        article_path = '{}/{}/employee/{}?pretty'.format(
            self.es_url, TEST_INDEX, TEST_DOC_ID)
        resp = requests.get(article_path, headers=COMMON_HEADERS)

        self.assertIn('I like to collect rock albums', resp.text,
            msg='Document not found({}): {}'.format(resp.status_code, resp.text))

    def test_elasticsearch_search(self):
        search_path = '{}/{}/employee/_search?pretty'.format(self.es_url, TEST_INDEX)

        search = {
            'query': {
                'match': {
                    'last_name': 'Smith'
                }
            }
        }

        resp = requests.get(
            search_path,
            data=json.dumps(search),
            headers=COMMON_HEADERS)

        self.assertIn('I like to collect rock albums', resp.text,
            msg='Search failed({}): {}'.format(resp.status_code, resp.text))

    @classmethod
    def _add_document(self, id, document):
        article_path = '{}/{}/employee/{}?pretty'.format(self.es_url, TEST_INDEX, id)
        resp = requests.put(
            article_path,
            data=json.dumps(document),
            headers=COMMON_HEADERS)
        # Pause to allow the document to be indexed
        time.sleep(1)
        return resp

    @classmethod
    def _delete_document(self, id):
        article_path = '{}/{}/employee/{}?pretty'.format(self.es_url, TEST_INDEX, id)
        resp = requests.delete(article_path, headers=COMMON_HEADERS)
        # Pause to allow the document to be indexed
        time.sleep(1)
        return resp

    @classmethod
    def _create_domain(cls, name=None, version=None):
        es_client = aws_stack.connect_to_service('es')
        name = name or TEST_DOMAIN_NAME
        kwargs = {}
        if version:
            kwargs['ElasticsearchVersion'] = version
        es_client.create_elasticsearch_domain(DomainName=name, **kwargs)
        assert_in(name, [d['DomainName'] for d in es_client.list_domain_names()['DomainNames']])

        # wait for completion status
        def check_cluster_ready(*args):
            status = es_client.describe_elasticsearch_domain(DomainName=name)
            assert status['DomainStatus']['Created']

        retry(check_cluster_ready, sleep=10, retries=12)
