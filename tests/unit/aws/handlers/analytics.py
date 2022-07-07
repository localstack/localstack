from unittest.mock import MagicMock, call

import pytest

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.aws.forwarder import create_aws_request_context
from localstack.aws.handlers.analytics import ServiceRequestCounter
from localstack.http import Response
from localstack.utils.analytics.service_request_aggregator import ServiceRequestInfo


@pytest.fixture(autouse=True)
def enable_analytics(monkeypatch):
    monkeypatch.setattr(config, "DISABLE_EVENTS", False)


class TestServiceRequestCounter:
    def test_starts_aggregator_after_first_call(self):
        aggregator = MagicMock()

        counter = ServiceRequestCounter(service_request_aggregator=aggregator)
        aggregator.start.assert_not_called()

        context = create_aws_request_context("s3", "ListBuckets")
        chain = HandlerChain([counter])
        chain.handle(context, Response())

        aggregator.start.assert_called_once()

        context = create_aws_request_context("s3", "ListBuckets")
        chain = HandlerChain([counter])
        chain.handle(context, Response())

        aggregator.start.assert_called_once()

    def test_ignores_requests_without_service(self):
        aggregator = MagicMock()
        counter = ServiceRequestCounter(service_request_aggregator=aggregator)

        chain = HandlerChain([counter])
        chain.handle(RequestContext(), Response())

        aggregator.start.assert_not_called()
        aggregator.add_request.assert_not_called()

    def test_ignores_requests_when_analytics_is_disabled(self, monkeypatch):
        monkeypatch.setattr(config, "DISABLE_EVENTS", True)

        aggregator = MagicMock()
        counter = ServiceRequestCounter(service_request_aggregator=aggregator)

        chain = HandlerChain([counter])
        chain.handle(
            create_aws_request_context("s3", "ListBuckets"),
            Response(),
        )

        aggregator.start.assert_not_called()
        aggregator.add_request.assert_not_called()

    def test_calls_aggregator(self):
        aggregator = MagicMock()
        counter = ServiceRequestCounter(service_request_aggregator=aggregator)

        chain = HandlerChain([counter])
        chain.handle(
            create_aws_request_context("s3", "ListBuckets"),
            Response(),
        )
        counter(
            chain,
            create_aws_request_context("s3", "HeadBucket", {"Bucket": "foobar"}),
            Response(),
        )

        aggregator.add_request.assert_has_calls(
            [
                call(ServiceRequestInfo("s3", "ListBuckets", 200)),
                call(ServiceRequestInfo("s3", "HeadBucket", 200)),
            ]
        )

    def test_parses_error_correctly(self):
        aggregator = MagicMock()
        counter = ServiceRequestCounter(service_request_aggregator=aggregator)

        chain = HandlerChain([counter])
        chain.handle(
            create_aws_request_context("opensearch", "DescribeDomain", {"DomainName": "foobar"}),
            Response(
                b'{"__type": "ResourceNotFoundException", "message": "Domain not found: foobar"}',
                404,
            ),
        )

        aggregator.add_request.assert_has_calls(
            [
                call(
                    ServiceRequestInfo(
                        "opensearch", "DescribeDomain", 404, "ResourceNotFoundException"
                    )
                ),
            ]
        )

    def test_invalid_error_behaves_like_botocore(self):
        aggregator = MagicMock()
        counter = ServiceRequestCounter(service_request_aggregator=aggregator)

        chain = HandlerChain([counter])
        chain.handle(
            create_aws_request_context("opensearch", "DescribeDomain", {"DomainName": "foobar"}),
            Response(b'{"__type": "ResourceN}', 404),
        )

        # for some reason botocore returns the status as the error Code when it parses an invalid error response
        aggregator.add_request.assert_has_calls(
            [
                call(ServiceRequestInfo("opensearch", "DescribeDomain", 404, "404")),
            ]
        )
