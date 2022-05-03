import pytest
from werkzeug.exceptions import NotFound
from werkzeug.routing import Map, Rule

from localstack.aws.protocol.op_router import GreedyPathConverter, RestServiceOperationRouter
from localstack.aws.spec import list_services, load_service
from localstack.http import Request


def _collect_services():
    for service in list_services():
        if service.protocol.startswith("rest"):
            yield service.service_name


@pytest.mark.parametrize(
    "service",
    _collect_services(),
)
@pytest.mark.param
def test_create_op_router_works_for_every_service(service):
    router = RestServiceOperationRouter(load_service(service))

    try:
        router.match(Request("GET", "/"))
    except NotFound:
        pass


def test_greedy_path_converter():
    # this test is mostly to document behavior

    router = Map(converters={"path": GreedyPathConverter}, merge_slashes=False)

    router.add(Rule("/test-bucket/<path:p>"))
    router.add(Rule("/some-route/<path:p>/bar"))

    matcher = router.bind("")
    # open-ended case
    assert matcher.match("/test-bucket//foo/bar") == (None, {"p": "/foo/bar"})
    assert matcher.match("/test-bucket//foo//bar") == (None, {"p": "/foo//bar"})
    assert matcher.match("/test-bucket//foo/bar/") == (None, {"p": "/foo/bar/"})

    # with a matching suffix
    assert matcher.match("/some-route//foo/bar") == (None, {"p": "/foo"})
    assert matcher.match("/some-route//foo//bar") == (None, {"p": "/foo/"})
    assert matcher.match("/some-route//foo/bar/bar") == (None, {"p": "/foo/bar"})
    with pytest.raises(NotFound):
        matcher.match("/some-route//foo/baz")


def test_s3_head_request():
    router = RestServiceOperationRouter(load_service("s3"))

    op, _ = router.match(Request("GET", "/my-bucket/my-key/"))
    assert op.name == "GetObject"

    op, _ = router.match(Request("HEAD", "/my-bucket/my-key/"))
    assert op.name == "HeadObject"


def test_trailing_slashes_are_not_strict():
    # this is tested against AWS. AWS is not strict about trailing slashes when routing operations.

    router = RestServiceOperationRouter(load_service("lambda"))

    op, _ = router.match(Request("GET", "/2015-03-31/functions"))
    assert op.name == "ListFunctions"

    op, _ = router.match(Request("GET", "/2015-03-31/functions/"))
    assert op.name == "ListFunctions"

    op, _ = router.match(Request("POST", "/2015-03-31/functions"))
    assert op.name == "CreateFunction"

    op, _ = router.match(Request("POST", "/2015-03-31/functions/"))
    assert op.name == "CreateFunction"
