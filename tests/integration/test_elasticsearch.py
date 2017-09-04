import json
import time
from botocore.exceptions import ClientError
from nose.tools import assert_raises, assert_equal, assert_true, assert_false
from localstack.utils.aws import aws_stack
from localstack.utils.common import safe_requests as requests

ES_URL = aws_stack.get_local_service_url('elasticsearch')
TEST_INDEX = 'megacorp'
TEST_DOC_ID = 1
COMMON_HEADERS = {
    'content-type': 'application/json',
    'Accept-encoding': 'identity'
}
TEST_DOMAIN_NAME = 'test_es_domain_1'


def setUp():
    document = {
        'first_name': 'Jane',
        'last_name': 'Smith',
        'age': 32,
        'about': 'I like to collect rock albums',
        'interests': ['music']
    }
    resp = add_document(TEST_DOC_ID, document)
    assert_equal(201, resp.status_code,
        msg='Request failed({}): {}'.format(resp.status_code, resp.text))


def tearDown():
    delete_document(TEST_DOC_ID)


def add_document(id, document):
    article_path = '{}/{}/employee/{}?pretty'.format(ES_URL, TEST_INDEX, id)
    resp = requests.put(
        article_path,
        data=json.dumps(document),
        headers=COMMON_HEADERS)
    # Pause to allow the document to be indexed
    time.sleep(1)
    return resp


def delete_document(id):
    article_path = '{}/{}/employee/{}?pretty'.format(ES_URL, TEST_INDEX, id)
    resp = requests.delete(article_path, headers=COMMON_HEADERS)
    # Pause to allow the document to be indexed
    time.sleep(1)
    return resp


def test_domain_creation():
    es_client = aws_stack.connect_to_service('es')

    # create ES domain
    es_client.create_elasticsearch_domain(DomainName=TEST_DOMAIN_NAME)
    assert_true(TEST_DOMAIN_NAME in
        [d['DomainName'] for d in es_client.list_domain_names()['DomainNames']])

    # make sure we cannot re-create same domain name
    assert_raises(ClientError, es_client.create_elasticsearch_domain, DomainName=TEST_DOMAIN_NAME)

    # get domain status
    status = es_client.describe_elasticsearch_domain(DomainName=TEST_DOMAIN_NAME)
    assert_equal(status['DomainStatus']['DomainName'], TEST_DOMAIN_NAME)
    assert_true(status['DomainStatus']['Created'])
    assert_false(status['DomainStatus']['Deleted'])

    # make sure domain deletion works
    es_client.delete_elasticsearch_domain(DomainName=TEST_DOMAIN_NAME)
    assert_false(TEST_DOMAIN_NAME in
        [d['DomainName'] for d in es_client.list_domain_names()['DomainNames']])


def test_elasticsearch_get_document():
    article_path = '{}/{}/employee/{}?pretty'.format(
        ES_URL, TEST_INDEX, TEST_DOC_ID)
    resp = requests.get(article_path, headers=COMMON_HEADERS)

    assert_true('I like to collect rock albums' in resp.text,
        msg='Document not found({}): {}'.format(resp.status_code, resp.text))


def test_elasticsearch_search():
    search_path = '{}/{}/employee/_search?pretty'.format(ES_URL, TEST_INDEX)

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

    assert_true('I like to collect rock albums' in resp.text,
        msg='Search failed({}): {}'.format(resp.status_code, resp.text))
