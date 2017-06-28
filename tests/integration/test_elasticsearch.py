import boto3
import json
import time
from botocore.exceptions import ClientError
from nose.tools import assert_raises, assert_equal, assert_true
from localstack import config
from localstack.utils.aws import aws_stack
from localstack.utils.common import safe_requests as requests

es_url = aws_stack.get_local_service_url('elasticsearch')
test_index = 'megacorp'
test_doc_id = 1
common_headers = {
    'content-type': 'application/json',
    'Accept-encoding': 'identity'
}


def setUp():
    document = {
        'first_name': 'Jane',
        'last_name': 'Smith',
        'age': 32,
        'about': 'I like to collect rock albums',
        'interests': ['music']
    }
    resp = add_document(test_doc_id, document)
    assert_equal(
        201,
        resp.status_code,
        msg='Request failed({}): {}'.format(
            resp.status_code,
            resp.text))


def tearDown():
    delete_document(test_doc_id)


def add_document(id, document):
    article_path = '{}/{}/employee/{}?pretty'.format(es_url, test_index, id)
    resp = requests.put(
        article_path,
        data=json.dumps(document),
        headers=common_headers)
    # Pause to allow the document to be indexed
    time.sleep(1)
    return resp


def delete_document(id):
    article_path = '{}/{}/employee/{}?pretty'.format(es_url, test_index, id)
    resp = requests.delete(
        article_path,
        headers=common_headers)
    # Pause to allow the document to be indexed
    time.sleep(1)
    return resp


def test_elasticsearch_get_document():
    article_path = '{}/{}/employee/{}?pretty'.format(
        es_url, test_index, test_doc_id)
    resp = requests.get(
        article_path,
        headers=common_headers)

    assert_true(
        'I like to collect rock albums' in resp.text,
        msg='Document not found({}): {}'.format(
            resp.status_code, resp.text))


def test_elasticsearch_search():
    search_path = '{}/{}/employee/_search?pretty'.format(es_url, test_index)

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
        headers=common_headers)

    assert_true(
        'I like to collect rock albums' in resp.text,
        msg='Search failed({}): {}'.format(
            resp.status_code,
            resp.text))
