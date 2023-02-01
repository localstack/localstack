import pytest

from localstack.aws.api import (
    RequestContext,
    ServiceException,
    ServiceRequest,
    ServiceResponse,
    handler,
)
from localstack.aws.forwarder import ForwardingFallbackDispatcher, NotImplementedAvoidFallbackError


def test_forwarding_fallback_dispatcher():
    # create a dummy provider which raises a NotImplementedError (triggering the fallthrough)
    class TestProvider:
        @handler(operation="TestOperation")
        def test_method(self, context):
            raise NotImplementedError

    test_provider = TestProvider()

    # create a dummy fallback function
    def test_request_forwarder(_, __) -> ServiceResponse:
        return "fallback-result"

    # invoke the function and expect the result from the fallback function
    dispatcher = ForwardingFallbackDispatcher(test_provider, test_request_forwarder)
    assert dispatcher["TestOperation"](RequestContext(), ServiceRequest()) == "fallback-result"


def test_forwarding_fallback_dispatcher_avoid_fallback():
    # create a dummy provider which raises a NotImplementedAvoidFallbackError (avoiding the fallthrough)
    class TestProvider:
        @handler(operation="TestOperation")
        def test_method(self, context):
            raise NotImplementedAvoidFallbackError

    test_provider = TestProvider()

    # create a dummy forwarding function which raises a ServiceException
    def test_request_forwarder(_, __) -> ServiceResponse:
        raise ServiceException

    # expect a NotImplementedError exception (and not the ServiceException from the fallthrough)
    dispatcher = ForwardingFallbackDispatcher(test_provider, test_request_forwarder)
    with pytest.raises(NotImplementedError):
        dispatcher["TestOperation"](RequestContext(), ServiceRequest())
