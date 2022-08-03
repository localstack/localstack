from io import BytesIO

import pytest

from localstack import config
from localstack.aws.api import ServiceException, handler
from localstack.services import moto
from localstack.services.moto import MotoFallbackDispatcher
from localstack.utils.common import short_uid, to_str


def test_call_with_sqs_creates_state_correctly():
    qname = f"queue-{short_uid()}"

    response = moto.call_moto(
        moto.create_aws_request_context("sqs", "CreateQueue", {"QueueName": qname}),
        include_response_metadata=True,
    )
    url = response["QueueUrl"]

    try:
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert response["QueueUrl"].endswith(f"/{qname}")

        response = moto.call_moto(moto.create_aws_request_context("sqs", "ListQueues"))
        assert url in response["QueueUrls"]
    finally:
        moto.call_moto(moto.create_aws_request_context("sqs", "DeleteQueue", {"QueueUrl": url}))

    response = moto.call_moto(moto.create_aws_request_context("sqs", "ListQueues"))
    assert url not in response.get("QueueUrls", [])


def test_call_sqs_invalid_call_raises_http_exception():
    with pytest.raises(ServiceException) as e:
        moto.call_moto(
            moto.create_aws_request_context(
                "sqs",
                "DeleteQueue",
                {
                    "QueueUrl": "http://0.0.0.0/nonexistingqueue",
                },
            )
        )
    e.match("The specified queue does not exist")


def test_call_non_implemented_operation():
    with pytest.raises(NotImplementedError):
        # we'll need to keep finding methods that moto doesn't implement ;-)
        moto.call_moto(
            moto.create_aws_request_context("athena", "DeleteDataCatalog", {"Name": "foo"})
        )


def test_proxy_non_implemented_operation():
    with pytest.raises(NotImplementedError):
        moto.proxy_moto(
            moto.create_aws_request_context("athena", "DeleteDataCatalog", {"Name": "foo"})
        )


def test_call_with_sqs_modifies_state_in_moto_backend():
    """Whitebox test to check that moto backends are populated correctly"""
    from moto.sqs.models import sqs_backends

    qname = f"queue-{short_uid()}"

    response = moto.call_moto(
        moto.create_aws_request_context("sqs", "CreateQueue", {"QueueName": qname})
    )
    url = response["QueueUrl"]
    assert qname in sqs_backends[config.AWS_REGION_US_EAST_1].queues
    moto.call_moto(moto.create_aws_request_context("sqs", "DeleteQueue", {"QueueUrl": url}))
    assert qname not in sqs_backends[config.AWS_REGION_US_EAST_1].queues


@pytest.mark.parametrize(
    "payload", ["foobar", b"foobar", BytesIO(b"foobar")], ids=["str", "bytes", "IO[bytes]"]
)
def test_call_s3_with_streaming_trait(payload, monkeypatch):
    monkeypatch.setenv("MOTO_S3_CUSTOM_ENDPOINTS", "s3.localhost.localstack.cloud:4566")

    bucket_name = f"bucket-{short_uid()}"
    key_name = "foobared"

    # create the bucket
    moto.call_moto(moto.create_aws_request_context("s3", "CreateBucket", {"Bucket": bucket_name}))

    moto.call_moto(
        moto.create_aws_request_context(
            "s3", "PutObject", {"Bucket": bucket_name, "Key": key_name, "Body": payload}
        )
    )

    # check whether it was created/received correctly
    response = moto.call_moto(
        moto.create_aws_request_context("s3", "GetObject", {"Bucket": bucket_name, "Key": key_name})
    )
    assert hasattr(
        response["Body"], "read"
    ), f"expected Body to be readable, was {type(response['Body'])}"
    assert response["Body"].read() == b"foobar"

    # cleanup
    moto.call_moto(
        moto.create_aws_request_context(
            "s3", "DeleteObject", {"Bucket": bucket_name, "Key": key_name}
        )
    )
    moto.call_moto(moto.create_aws_request_context("s3", "DeleteBucket", {"Bucket": bucket_name}))


def test_call_include_response_metadata():
    ctx = moto.create_aws_request_context("sqs", "ListQueues")

    response = moto.call_moto(ctx)
    assert "ResponseMetadata" not in response

    response = moto.call_moto(ctx, include_response_metadata=True)
    assert "ResponseMetadata" in response


def test_call_with_modified_request():
    from moto.sqs.models import sqs_backends

    qname1 = f"queue-{short_uid()}"
    qname2 = f"queue-{short_uid()}"

    context = moto.create_aws_request_context("sqs", "CreateQueue", {"QueueName": qname1})
    response = moto.call_moto_with_request(context, {"QueueName": qname2})  # overwrite old request

    url = response["QueueUrl"]
    assert qname2 in sqs_backends[config.AWS_REGION_US_EAST_1].queues
    assert qname1 not in sqs_backends[config.AWS_REGION_US_EAST_1].queues

    moto.call_moto(moto.create_aws_request_context("sqs", "DeleteQueue", {"QueueUrl": url}))


def test_call_with_es_creates_state_correctly():
    domain_name = f"domain-{short_uid()}"
    response = moto.call_moto(
        moto.create_aws_request_context(
            "es",
            "CreateElasticsearchDomain",
            {
                "DomainName": domain_name,
                "ElasticsearchVersion": "7.10",
            },
        ),
        include_response_metadata=True,
    )

    try:
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert response["DomainStatus"]["DomainName"] == domain_name
        assert response["DomainStatus"]["ElasticsearchVersion"] == "7.10"
    finally:
        response = moto.call_moto(
            moto.create_aws_request_context(
                "es", "DeleteElasticsearchDomain", {"DomainName": domain_name}
            ),
            include_response_metadata=True,
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200


def test_call_multi_region_backends():
    from moto.sqs.models import sqs_backends

    qname_us = f"queue-us-{short_uid()}"
    qname_eu = f"queue-eu-{short_uid()}"

    moto.call_moto(
        moto.create_aws_request_context(
            "sqs", "CreateQueue", {"QueueName": qname_us}, region="us-east-1"
        )
    )
    moto.call_moto(
        moto.create_aws_request_context(
            "sqs", "CreateQueue", {"QueueName": qname_eu}, region="eu-central-1"
        )
    )

    assert qname_us in sqs_backends["us-east-1"].queues
    assert qname_eu not in sqs_backends["us-east-1"].queues

    assert qname_us not in sqs_backends["eu-central-1"].queues
    assert qname_eu in sqs_backends["eu-central-1"].queues

    del sqs_backends["us-east-1"].queues[qname_us]
    del sqs_backends["eu-central-1"].queues[qname_eu]


def test_proxy_with_sqs_invalid_call_returns_error():
    response = moto.proxy_moto(
        moto.create_aws_request_context(
            "sqs",
            "DeleteQueue",
            {
                "QueueUrl": "http://0.0.0.0/nonexistingqueue",
            },
        )
    )

    assert response.status_code == 400
    assert "NonExistentQueue" in to_str(response.data)


def test_proxy_with_sqs_returns_http_response():
    qname = f"queue-{short_uid()}"

    response = moto.proxy_moto(
        moto.create_aws_request_context("sqs", "CreateQueue", {"QueueName": qname})
    )

    assert response.status_code == 200
    assert f"{qname}</QueueUrl>" in to_str(response.data)
    assert "x-amzn-requestid" in response.headers


class FakeSqsApi:
    @handler("ListQueues", expand=False)
    def list_queues(self, context, request):
        raise NotImplementedError

    @handler("CreateQueue", expand=False)
    def create_queue(self, context, request):
        raise NotImplementedError


class FakeSqsProvider(FakeSqsApi):
    def __init__(self) -> None:
        super().__init__()
        self.calls = []

    @handler("ListQueues", expand=False)
    def list_queues(self, context, request):
        self.calls.append(context)
        return moto.call_moto(context)


def test_moto_fallback_dispatcher():
    provider = FakeSqsProvider()
    dispatcher = MotoFallbackDispatcher(provider)

    assert "ListQueues" in dispatcher
    assert "CreateQueue" in dispatcher

    def _dispatch(action, params):
        context = moto.create_aws_request_context("sqs", action, params)
        return dispatcher[action](context, params)

    qname = f"queue-{short_uid()}"
    # when falling through the dispatcher returns an HTTP response
    http_response = _dispatch("CreateQueue", {"QueueName": qname})
    assert http_response.status_code == 200

    # this returns an
    response = _dispatch("ListQueues", None)
    assert len(provider.calls) == 1
    assert len([url for url in response["QueueUrls"] if qname in url])


def test_request_with_response_header_location_fields():
    # CreateHostedZoneResponse has a member "Location" that's located in the headers
    zone_name = f"zone-{short_uid()}.com"
    request = moto.create_aws_request_context(
        "route53", "CreateHostedZone", {"Name": zone_name, "CallerReference": "test"}
    )
    response = moto.call_moto(request, include_response_metadata=True)
    # assert response["Location"]  # FIXME: this is required according to the spec, but not returned by moto
    assert response["HostedZone"]["Id"]

    # clean up
    moto.call_moto(
        moto.create_aws_request_context(
            "route53", "DeleteHostedZone", {"Id": response["HostedZone"]["Id"]}
        )
    )
