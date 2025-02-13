import pytest
from werkzeug.exceptions import NotFound
from werkzeug.routing import Map, Rule
from localstack.aws.protocol.op_router import RestServiceOperationRouter
from localstack.aws.spec import list_services, load_service
from localstack.http import Request
from localstack.http.router import GreedyPathConverter

def _collect_services():
    '''"""Auto-generated docstring for function '_collect_services'."""'''
    for service in list_services():
        if service.protocol.startswith('rest'):
            yield service.service_name

@pytest.mark.parametrize('service', _collect_services())
@pytest.mark.param
def test_create_op_router_works_for_every_service(service):
    '''"""Auto-generated docstring for function 'test_create_op_router_works_for_every_service'."""'''
    router = RestServiceOperationRouter(load_service(service))
    try:
        router.match(Request('GET', '/'))
    except NotFound:
        pass

def test_greedy_path_converter():
    '''"""Auto-generated docstring for function 'test_greedy_path_converter'."""'''
    router = Map(converters={'path': GreedyPathConverter}, merge_slashes=False)
    router.add(Rule('/test-bucket/<path:p>'))
    router.add(Rule('/some-route/<path:p>/bar'))
    matcher = router.bind('')
    assert matcher.match('/test-bucket//foo/bar') == (None, {'p': '/foo/bar'})
    assert matcher.match('/test-bucket//foo//bar') == (None, {'p': '/foo//bar'})
    assert matcher.match('/test-bucket//foo/bar/') == (None, {'p': '/foo/bar/'})
    assert matcher.match('/some-route//foo/bar') == (None, {'p': '/foo'})
    assert matcher.match('/some-route//foo//bar') == (None, {'p': '/foo/'})
    assert matcher.match('/some-route//foo/bar/bar') == (None, {'p': '/foo/bar'})
    with pytest.raises(NotFound):
        matcher.match('/some-route//foo/baz')

def test_s3_head_request():
    '''"""Auto-generated docstring for function 'test_s3_head_request'."""'''
    router = RestServiceOperationRouter(load_service('s3'))
    op, _ = router.match(Request('GET', '/my-bucket/my-key/'))
    assert op.name == 'GetObject'
    op, _ = router.match(Request('HEAD', '/my-bucket/my-key/'))
    assert op.name == 'HeadObject'

def test_basic_param_extraction():
    '''"""Auto-generated docstring for function 'test_basic_param_extraction'."""'''
    router = RestServiceOperationRouter(load_service('apigateway'))
    op, params = router.match(Request('POST', '/restapis/myrestapi/deployments'))
    assert op.name == 'CreateDeployment'
    assert params == {'restapi_id': 'myrestapi'}
    with pytest.raises(NotFound):
        router.match(Request('POST', '/restapis/myrestapi//deployments'))

def test_trailing_slashes_are_not_strict():
    '''"""Auto-generated docstring for function 'test_trailing_slashes_are_not_strict'."""'''
    router = RestServiceOperationRouter(load_service('lambda'))
    op, _ = router.match(Request('GET', '/2015-03-31/functions'))
    assert op.name == 'ListFunctions'
    op, _ = router.match(Request('GET', '/2015-03-31/functions/'))
    assert op.name == 'ListFunctions'
    op, _ = router.match(Request('POST', '/2015-03-31/functions'))
    assert op.name == 'CreateFunction'
    op, _ = router.match(Request('POST', '/2015-03-31/functions/'))
    assert op.name == 'CreateFunction'

def test_s3_query_args_routing():
    '''"""Auto-generated docstring for function 'test_s3_query_args_routing'."""'''
    router = RestServiceOperationRouter(load_service('s3'))
    op, params = router.match(Request('DELETE', '/mybucket?delete'))
    assert op.name == 'DeleteBucket'
    assert params == {'Bucket': 'mybucket'}
    op, params = router.match(Request('DELETE', '/mybucket/?delete'))
    assert op.name == 'DeleteBucket'
    assert params == {'Bucket': 'mybucket'}
    op, params = router.match(Request('DELETE', '/mybucket/mykey?delete'))
    assert op.name == 'DeleteObject'
    assert params == {'Bucket': 'mybucket', 'Key': 'mykey'}
    op, params = router.match(Request('DELETE', '/mybucket/mykey/?delete'))
    assert op.name == 'DeleteObject'
    assert params == {'Bucket': 'mybucket', 'Key': 'mykey'}

def test_s3_bucket_operation_with_trailing_slashes():
    '''"""Auto-generated docstring for function 'test_s3_bucket_operation_with_trailing_slashes'."""'''
    router = RestServiceOperationRouter(load_service('s3'))
    op, params = router.match(Request('GET', '/mybucket'))
    assert op.name == 'ListObjects'
    assert params == {'Bucket': 'mybucket'}
    op, params = router.match(Request('Get', '/mybucket/'))
    assert op.name == 'ListObjects'
    assert params == {'Bucket': 'mybucket'}

def test_s3_object_operation_with_trailing_slashes():
    '''"""Auto-generated docstring for function 'test_s3_object_operation_with_trailing_slashes'."""'''
    router = RestServiceOperationRouter(load_service('s3'))
    op, params = router.match(Request('GET', '/mybucket/mykey'))
    assert op.name == 'GetObject'
    assert params == {'Bucket': 'mybucket', 'Key': 'mykey'}
    op, params = router.match(Request('GET', '/mybucket/mykey/'))
    assert op.name == 'GetObject'
    assert params == {'Bucket': 'mybucket', 'Key': 'mykey'}

def test_s3_bucket_operation_with_double_slashes():
    '''"""Auto-generated docstring for function 'test_s3_bucket_operation_with_double_slashes'."""'''
    router = RestServiceOperationRouter(load_service('s3'))
    op, params = router.match(Request('GET', '/mybucket//mykey'))
    assert op.name == 'GetObject'
    assert params == {'Bucket': 'mybucket', 'Key': '/mykey'}