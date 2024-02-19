from unittest import mock

from localstack.aws.api import RequestContext
from localstack.aws.chain import CompositeHandler, HandlerChain
from localstack.http import Response


class TestCompositeHandler:
    def test_composite_handler_stops_handler_chain(self):
        def inner1(_chain: HandlerChain, request: RequestContext, response: Response):
            _chain.stop()

        inner2 = mock.MagicMock()
        outer1 = mock.MagicMock()
        outer2 = mock.MagicMock()
        response1 = mock.MagicMock()
        finalizer = mock.MagicMock()

        chain = HandlerChain()

        composite = CompositeHandler()
        composite.handlers.append(inner1)
        composite.handlers.append(inner2)

        chain.request_handlers.append(outer1)
        chain.request_handlers.append(composite)
        chain.request_handlers.append(outer2)
        chain.response_handlers.append(response1)
        chain.finalizers.append(finalizer)

        chain.handle(RequestContext(), Response())
        outer1.assert_called_once()
        outer2.assert_not_called()
        inner2.assert_not_called()
        response1.assert_called_once()
        finalizer.assert_called_once()

    def test_composite_handler_terminates_handler_chain(self):
        def inner1(_chain: HandlerChain, request: RequestContext, response: Response):
            _chain.terminate()

        inner2 = mock.MagicMock()
        outer1 = mock.MagicMock()
        outer2 = mock.MagicMock()
        response1 = mock.MagicMock()
        finalizer = mock.MagicMock()

        chain = HandlerChain()

        composite = CompositeHandler()
        composite.handlers.append(inner1)
        composite.handlers.append(inner2)

        chain.request_handlers.append(outer1)
        chain.request_handlers.append(composite)
        chain.request_handlers.append(outer2)
        chain.response_handlers.append(response1)
        chain.finalizers.append(finalizer)

        chain.handle(RequestContext(), Response())
        outer1.assert_called_once()
        outer2.assert_not_called()
        inner2.assert_not_called()
        response1.assert_not_called()
        finalizer.assert_called_once()

    def test_composite_handler_with_not_return_on_stop(self):
        def inner1(_chain: HandlerChain, request: RequestContext, response: Response):
            _chain.stop()

        inner2 = mock.MagicMock()
        outer1 = mock.MagicMock()
        outer2 = mock.MagicMock()
        response1 = mock.MagicMock()
        finalizer = mock.MagicMock()

        chain = HandlerChain()

        composite = CompositeHandler(return_on_stop=False)
        composite.handlers.append(inner1)
        composite.handlers.append(inner2)

        chain.request_handlers.append(outer1)
        chain.request_handlers.append(composite)
        chain.request_handlers.append(outer2)
        chain.response_handlers.append(response1)
        chain.finalizers.append(finalizer)

        chain.handle(RequestContext(), Response())
        outer1.assert_called_once()
        outer2.assert_not_called()
        inner2.assert_called_once()
        response1.assert_called_once()
        finalizer.assert_called_once()

    def test_composite_handler_continues_handler_chain(self):
        inner1 = mock.MagicMock()
        inner2 = mock.MagicMock()
        outer1 = mock.MagicMock()
        outer2 = mock.MagicMock()
        response1 = mock.MagicMock()
        finalizer = mock.MagicMock()

        chain = HandlerChain()

        composite = CompositeHandler()
        composite.handlers.append(inner1)
        composite.handlers.append(inner2)

        chain.request_handlers.append(outer1)
        chain.request_handlers.append(composite)
        chain.request_handlers.append(outer2)
        chain.response_handlers.append(response1)
        chain.finalizers.append(finalizer)

        chain.handle(RequestContext(), Response())
        outer1.assert_called_once()
        outer2.assert_called_once()
        inner1.assert_called_once()
        inner2.assert_called_once()
        response1.assert_called_once()
        finalizer.assert_called_once()

    def test_composite_handler_exception_calls_outer_exception_handlers(self):
        def inner1(_chain: HandlerChain, request: RequestContext, response: Response):
            raise ValueError()

        inner2 = mock.MagicMock()
        outer1 = mock.MagicMock()
        outer2 = mock.MagicMock()
        exception_handler = mock.MagicMock()
        response1 = mock.MagicMock()
        finalizer = mock.MagicMock()

        chain = HandlerChain()

        composite = CompositeHandler()
        composite.handlers.append(inner1)
        composite.handlers.append(inner2)

        chain.request_handlers.append(outer1)
        chain.request_handlers.append(composite)
        chain.request_handlers.append(outer2)
        chain.exception_handlers.append(exception_handler)
        chain.response_handlers.append(response1)
        chain.finalizers.append(finalizer)

        chain.handle(RequestContext(), Response())
        outer1.assert_called_once()
        outer2.assert_not_called()
        inner2.assert_not_called()
        exception_handler.assert_called_once()
        response1.assert_called_once()
        finalizer.assert_called_once()
