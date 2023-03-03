"""
This test file captures the _current_ state of returning URLs before making
sweeping changes. This is to ensure that the refactoring does not cause
external breaking behaviour. In the future we can update this test suite to
correspond to the behaviour we want, and we get a todo list of things to
change 😂
"""
import pytest

from localstack import config, constants
from localstack.utils.strings import short_uid

# TODO: how do we test `localstack_hostname` - this variable configures the
# host that services make requests to when starting up (e.g. opensearch) and
# they won't start if we override the variable.


pytestmark = [pytest.mark.only_localstack]


class TestOpenSearch:
    """
    OpenSearch does not respect any customisations and just returns a domain with localhost.localstack.cloud in.
    """

    def test_default_strategy(
        self, opensearch_client, opensearch_wait_for_cluster, patch_hostnames
    ):
        domain_name = f"domain-{short_uid()}"
        res = opensearch_client.create_domain(DomainName=domain_name)
        opensearch_wait_for_cluster(domain_name)
        endpoint = res["DomainStatus"]["Endpoint"]

        hostname_external, localstack_hostname = patch_hostnames

        assert constants.LOCALHOST_HOSTNAME in endpoint

        assert hostname_external not in endpoint
        assert localstack_hostname not in endpoint

    def test_port_strategy(
        self, monkeypatch, opensearch_client, opensearch_wait_for_cluster, patch_hostnames
    ):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "port")

        domain_name = f"domain-{short_uid()}"
        res = opensearch_client.create_domain(DomainName=domain_name)
        opensearch_wait_for_cluster(domain_name)
        endpoint = res["DomainStatus"]["Endpoint"]

        hostname_external, localstack_hostname = patch_hostnames

        if config.is_in_docker:
            assert constants.LOCALHOST in endpoint
        else:
            assert "127.0.0.1" in endpoint

        assert hostname_external not in endpoint
        assert localstack_hostname not in endpoint
        assert constants.LOCALHOST_HOSTNAME not in endpoint

    def test_path_strategy(
        self, monkeypatch, opensearch_client, opensearch_wait_for_cluster, patch_hostnames
    ):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "path")

        domain_name = f"domain-{short_uid()}"
        res = opensearch_client.create_domain(DomainName=domain_name)
        opensearch_wait_for_cluster(domain_name)
        endpoint = res["DomainStatus"]["Endpoint"]

        hostname_external, localstack_hostname = patch_hostnames

        assert "localhost" in endpoint

        assert hostname_external not in endpoint
        assert localstack_hostname not in endpoint
        assert constants.LOCALHOST_HOSTNAME not in endpoint


class TestS3:
    @pytest.mark.skipif(
        condition=config.LEGACY_S3_PROVIDER, reason="Not implemented for legacy provider"
    )
    def test_non_us_east_1_location(
        self, monkeypatch, patch_hostnames, s3_resource, s3_client, cleanups
    ):
        monkeypatch.setattr(config, "LEGACY_S3_PROVIDER", False)
        monkeypatch.setenv("PROVIDER_OVERRIDE_S3", "asf")

        bucket_name = f"bucket-{short_uid()}"
        res = s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={
                "LocationConstraint": "eu-west-1",
            },
        )

        def cleanup():
            bucket = s3_resource.Bucket(bucket_name)
            bucket.objects.all().delete()
            bucket.object_versions.all().delete()
            bucket.delete()

        cleanups.append(cleanup)

        hostname_external, localstack_hostname = patch_hostnames

        url = res["Location"]

        assert hostname_external in url

        assert localstack_hostname not in url
        assert constants.LOCALHOST_HOSTNAME not in url

    def test_multipart_upload(self, patch_hostnames, s3_bucket, s3_client):
        key_name = f"key-{short_uid()}"
        upload_id = s3_client.create_multipart_upload(Bucket=s3_bucket, Key=key_name)["UploadId"]
        part_etag = s3_client.upload_part(
            Bucket=s3_bucket, Key=key_name, Body=b"bytes", PartNumber=1, UploadId=upload_id
        )["ETag"]
        res = s3_client.complete_multipart_upload(
            Bucket=s3_bucket,
            Key=key_name,
            MultipartUpload={"Parts": [{"ETag": part_etag, "PartNumber": 1}]},
            UploadId=upload_id,
        )
        location = res["Location"]

        hostname_external, localstack_hostname = patch_hostnames

        assert hostname_external in location

        assert localstack_hostname not in location
        assert constants.LOCALHOST_HOSTNAME not in location

    @pytest.mark.parametrize("method", ["put_object", "get_object", "head_object"])
    def test_presigned_urls(self, method, patch_hostnames, s3_bucket, s3_client):
        key_name = f"key-{short_uid()}"
        url = s3_client.generate_presigned_url(
            ClientMethod=method, Params=dict(Bucket=s3_bucket, Key=key_name)
        )

        hostname_external, localstack_hostname = patch_hostnames

        assert constants.LOCALHOST_HOSTNAME in url
        assert hostname_external not in url
        assert localstack_hostname not in url

    def test_presigned_post(self, patch_hostnames, s3_bucket, s3_client):
        key_name = f"key-{short_uid()}"
        url = s3_client.generate_presigned_post(Bucket=s3_bucket, Key=key_name)["url"]

        hostname_external, localstack_hostname = patch_hostnames

        assert constants.LOCALHOST_HOSTNAME in url
        assert hostname_external not in url
        assert localstack_hostname not in url


class TestSQS:
    """
    Test all combinations of:

    * endpoint_strategy
    * sqs_port_external
    * hostname_external
    """

    def test_off_strategy_without_external_port(
        self, monkeypatch, sqs_create_queue, patch_hostnames
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", "off")

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        hostname_external, localstack_hostname = patch_hostnames
        assert constants.LOCALHOST in queue_url
        assert queue_name in queue_url

        assert hostname_external not in queue_url
        assert constants.LOCALHOST_HOSTNAME not in queue_url
        assert localstack_hostname not in queue_url

    def test_off_strategy_with_external_port(self, monkeypatch, sqs_create_queue, patch_hostnames):
        external_port = 12345
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", "off")
        monkeypatch.setattr(config, "SQS_PORT_EXTERNAL", external_port)

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        hostname_external, localstack_hostname = patch_hostnames
        assert hostname_external in queue_url
        assert str(external_port) in queue_url
        assert queue_name in queue_url

        assert localstack_hostname not in queue_url

    @pytest.mark.parametrize("external_port", [0, 12345])
    def test_domain_strategy(self, external_port, monkeypatch, sqs_create_queue, patch_hostnames):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", "domain")
        monkeypatch.setattr(config, "SQS_PORT_EXTERNAL", external_port)

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        hostname_external, localstack_hostname = patch_hostnames
        assert constants.LOCALHOST_HOSTNAME in queue_url
        assert queue_name in queue_url

        assert hostname_external not in queue_url
        assert localstack_hostname not in queue_url

    @pytest.mark.parametrize("external_port", [0, 12345])
    def test_path_strategy(self, external_port, monkeypatch, sqs_create_queue, patch_hostnames):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", "path")
        monkeypatch.setattr(config, "SQS_PORT_EXTERNAL", external_port)

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        hostname_external, localstack_hostname = patch_hostnames
        assert "localhost" in queue_url
        assert queue_name in queue_url

        assert constants.LOCALHOST_HOSTNAME not in queue_url
        assert hostname_external not in queue_url
        assert localstack_hostname not in queue_url
