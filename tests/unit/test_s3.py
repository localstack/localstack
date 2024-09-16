import datetime
import os
import re
from io import BytesIO
from urllib.parse import urlparse

import pytest
import zoneinfo

from localstack.aws.api import RequestContext
from localstack.aws.api.s3 import InvalidArgument
from localstack.config import S3_VIRTUAL_HOSTNAME
from localstack.constants import LOCALHOST
from localstack.http import Request
from localstack.services.s3 import presigned_url
from localstack.services.s3 import utils as s3_utils
from localstack.services.s3.codec import AwsChunkedDecoder
from localstack.services.s3.constants import S3_CHUNK_SIZE
from localstack.services.s3.exceptions import MalformedXML
from localstack.services.s3.models import S3Multipart, S3Object, S3Part
from localstack.services.s3.storage.ephemeral import EphemeralS3ObjectStore
from localstack.services.s3.validation import validate_canned_acl


class TestS3Utils:
    @pytest.mark.parametrize(
        "path, headers, expected_bucket, expected_key",
        [
            ("/bucket/keyname", {"host": f"{LOCALHOST}:4566"}, "bucket", "keyname"),
            ("/bucket//keyname", {"host": f"{LOCALHOST}:4566"}, "bucket", "/keyname"),
            ("/keyname", {"host": f"bucket.{S3_VIRTUAL_HOSTNAME}:4566"}, "bucket", "keyname"),
            ("//keyname", {"host": f"bucket.{S3_VIRTUAL_HOSTNAME}:4566"}, "bucket", "/keyname"),
            ("/", {"host": f"{S3_VIRTUAL_HOSTNAME}:4566"}, None, None),
            ("/", {"host": "bucket.s3-ap-northeast-1.amazonaws.com:4566"}, "bucket", None),
            ("/", {"host": "bucket.s3-ap-south-1.amazonaws.com"}, "bucket", None),
            ("/", {"host": "bucket.s3-eu-west-1.amazonaws.com"}, "bucket", None),
            ("/", {"host": "bucket.s3.amazonaws.com"}, "bucket", None),
            ("/", {"host": "bucket.s3.ap-northeast-1.amazonaws.com"}, "bucket", None),
            ("/", {"host": "bucket.s3.ap-southeast-1.amazonaws.com"}, "bucket", None),
            ("/", {"host": "bucket.s3.ca-central-1.amazonaws.com"}, "bucket", None),
            ("/", {"host": "bucket.s3.cn-north-1.amazonaws.com.cn"}, "bucket", None),
            ("/", {"host": "bucket.s3.dualstack.ap-northeast-1.amazonaws.com"}, "bucket", None),
            ("/", {"host": "bucket.s3.dualstack.eu-west-1.amazonaws.com"}, "bucket", None),
            ("/", {"host": "bucket.s3.eu-central-1.amazonaws.com"}, "bucket", None),
            ("/", {"host": "bucket.s3.eu-west-1.amazonaws.com"}, "bucket", None),
            ("/", {"host": "bucket.s3.sa-east-1.amazonaws.com"}, "bucket", None),
            ("/", {"host": "bucket.s3.us-east-1.amazonaws.com"}, "bucket", None),
            ("/", {"host": "bucket.s3.localhost.localstack.cloud"}, "bucket", None),
            ("/", {"host": "bucket-1.s3-website.localhost.localstack.cloud"}, "bucket-1", None),
            ("/", {"host": "bucket.localhost.localstack.cloud"}, None, None),
            ("/", {"host": "localhost.localstack.cloud"}, None, None),
            ("/", {"host": "test.dynamodb.amazonaws.com"}, None, None),
            ("/", {"host": "dynamodb.amazonaws.com"}, None, None),
            ("/", {"host": "bucket.s3.randomdomain.com"}, "bucket", None),
            ("/", {"host": "bucket.s3.example.domain.com:4566"}, "bucket", None),
        ],
    )
    def test_extract_bucket_name_and_key_from_headers_and_path(
        self, path, headers, expected_bucket, expected_key
    ):
        bucket, key = s3_utils.extract_bucket_name_and_key_from_headers_and_path(headers, path)
        assert bucket == expected_bucket
        assert key == expected_key

    # test whether method correctly distinguishes between hosted and path style bucket references
    # path style format example: https://s3.{region}.localhost.localstack.cloud:4566/{bucket-name}/{key-name}
    # hosted style format example: http://{bucket-name}.s3.{region}localhost.localstack.cloud:4566/
    # region is optional in localstack
    def test_uses_virtual_host_addressing(self):
        addresses = [
            ({"host": f"aws.{LOCALHOST}:4566"}, None),
            ({"host": f"{LOCALHOST}.aws:4566"}, None),
            ({"host": f"{LOCALHOST}.swa:4566"}, None),
            ({"host": f"swa.{LOCALHOST}:4566"}, None),
            ({"host": "bucket.s3.localhost.localstack.cloud"}, "bucket"),
            ({"host": "bucket.s3.eu-west-1.amazonaws.com"}, "bucket"),
            ({"host": "s3.eu-west-1.localhost.localstack.cloud/bucket"}, None),
            ({"host": "s3.localhost.localstack.cloud"}, None),
            ({"host": "s3.localhost.localstack.cloud:4566"}, None),
            ({"host": "bucket.s3.eu-west-1.localhost.localstack.cloud"}, "bucket"),
            ({"host": "bucket.s3.localhost.localstack.cloud/key"}, "bucket"),
            ({"host": "bucket.s3.eu-west-1.amazonaws.com"}, "bucket"),
            ({"host": "bucket.s3.amazonaws.com"}, "bucket"),
            ({"host": "notabucket.amazonaws.com"}, None),
            ({"host": "s3.amazonaws.com"}, None),
            ({"host": "s3.eu-west-1.amazonaws.com"}, None),
            ({"host": "tests3.eu-west-1.amazonaws.com"}, None),
        ]
        for headers, expected_result in addresses:
            assert s3_utils.uses_host_addressing(headers) == expected_result

    def test_virtual_host_matching(self):
        hosts = [
            ("bucket.s3.localhost.localstack.cloud", "bucket", None),
            ("bucket.s3.eu-west-1.amazonaws.com", "bucket", "eu-west-1"),
            ("test-bucket.s3.eu-west-1.localhost.localstack.cloud", "test-bucket", "eu-west-1"),
            ("bucket.s3.notrealregion-west-1.localhost.localstack.cloud", "bucket", None),
            ("mybucket.s3.amazonaws.com", "mybucket", None),
        ]
        compiled_regex = re.compile(s3_utils.S3_VIRTUAL_HOSTNAME_REGEX)
        for host, bucket_name, region_name in hosts:
            result = compiled_regex.match(host)
            assert result.group("bucket") == bucket_name
            assert result.group("region") == region_name

    def test_is_valid_canonical_id(self):
        canonical_ids = [
            (
                "0f84b30102b8e116121884e982fedc9d76715877fc810605f7ba5dca143b3bb0",
                True,
            ),  # 64 len hex string
            ("f945fc46e86d3af9b2ebf8bda159f94b8f6be81413a5a2e21e8fd3a059de55a9", True),
            ("73E7AFD3413526244BDA3D3E08CF191115773EFF5D875B4860963A71AB7C13E6", True),
            ("0f84b30102b8e116121884e982fedc9d76715877fc810605f7ba5dca143b3bb", False),
            ("0f84b30102b8e116121884e982fedc9d76715877fc810605f7ba5dca143b3bb00", False),
            ("0f84b30102b8e116121884e982fedc9d76715877fc810605f7ba5dca143b3bbz", False),
            ("KXy1MCaCAUmbwQGOqVkJrzIDEbDPg4mLwMMzj8CyFdmbZx-JAm158soGrLlPZwXG", False),
            ("KXy1MCaCAUmbwQGOqVkJrzIDEbDPg4mLwMMzj8CyFdmbZx", False),
        ]
        for canonical_id, expected_result in canonical_ids:
            assert s3_utils.is_valid_canonical_id(canonical_id) == expected_result

    @pytest.mark.parametrize(
        "request_member, permission, response_header",
        [
            ("GrantFullControl", "FULL_CONTROL", "x-amz-grant-full-control"),
            ("GrantRead", "READ", "x-amz-grant-read"),
            ("GrantReadACP", "READ_ACP", "x-amz-grant-read-acp"),
            ("GrantWrite", "WRITE", "x-amz-grant-write"),
            ("GrantWriteACP", "WRITE_ACP", "x-amz-grant-write-acp"),
        ],
    )
    def test_get_permission_from_request_header_to_response_header(
        self, request_member, permission, response_header
    ):
        """
        Test to transform shape member names into their header location
        We could maybe use the specs for this
        """
        parsed_permission = s3_utils.get_permission_from_header(request_member)
        assert parsed_permission == permission
        assert s3_utils.get_permission_header_name(parsed_permission) == response_header

    @pytest.mark.parametrize(
        "canned_acl, raise_exception",
        [
            ("private", False),
            ("public-read", False),
            ("public-read-write", False),
            ("authenticated-read", False),
            ("aws-exec-read", False),
            ("bucket-owner-read", False),
            ("bucket-owner-full-control", False),
            ("not-a-canned-one", True),
            ("aws--exec-read", True),
            ("log-delivery-write", False),
        ],
    )
    def test_validate_canned_acl(self, canned_acl, raise_exception):
        if raise_exception:
            with pytest.raises(InvalidArgument) as e:
                validate_canned_acl(canned_acl)
            assert e.value.ArgumentName == "x-amz-acl"
            assert e.value.ArgumentValue == canned_acl

        else:
            validate_canned_acl(canned_acl)

    def test_s3_bucket_name(self):
        bucket_names = [
            ("docexamplebucket1", True),
            ("log-delivery-march-2020", True),
            ("my-hosted-content", True),
            ("docexamplewebsite.com", True),
            ("www.docexamplewebsite.com", True),
            ("my.example.s3.bucket", True),
            ("doc_example_bucket", False),
            ("DocExampleBucket", False),
            ("doc-example-bucket-", False),
        ]

        for bucket_name, expected_result in bucket_names:
            assert s3_utils.is_bucket_name_valid(bucket_name) == expected_result

    def test_verify_checksum(self):
        valid_checksums = [
            (
                "SHA256",
                b"test data..",
                {"ChecksumSHA256": "2l26x0trnT0r2AvakoFk2MB7eKVKzYESLMxSAKAzoik="},
            ),
            ("CRC32", b"test data..", {"ChecksumCRC32": "cZWHwQ=="}),
            ("CRC32C", b"test data..", {"ChecksumCRC32C": "Pf4upw=="}),
            ("SHA1", b"test data..", {"ChecksumSHA1": "B++3uSfJMSHWToQMQ1g6lIJY5Eo="}),
            (
                "SHA1",
                b"test data..",
                {"ChecksumSHA1": "B++3uSfJMSHWToQMQ1g6lIJY5Eo=", "ChecksumCRC32C": "test"},
            ),
        ]

        for checksum_algorithm, data, request in valid_checksums:
            # means that it did not raise an exception
            assert s3_utils.verify_checksum(checksum_algorithm, data, request) is None

        invalid_checksums = [
            (
                "sha256&",
                b"test data..",
                {"ChecksumSHA256": "2l26x0trnT0r2AvakoFk2MB7eKVKzYESLMxSAKAzoik="},
            ),
            (
                "sha256",
                b"test data..",
                {"ChecksumSHA256": "2l26x0trnT0r2AvakoFk2MB7eKVKzYESLMxSAKAzoik="},
            ),
            ("CRC32", b"test data..", {"ChecksumCRC32": "cZWHwQ==="}),
            ("CRC32", b"test data.", {"ChecksumCRC32C": "Pf4upw=="}),
            ("SHA1", b"test da\nta..", {"ChecksumSHA1": "B++3uSfJMSHWToQMQ1g6lIJY5Eo="}),
        ]
        for checksum_algorithm, data, request in invalid_checksums:
            with pytest.raises(Exception):
                s3_utils.verify_checksum(checksum_algorithm, data, request)

    @pytest.mark.parametrize(
        "presign_url, expected_output_bucket, expected_output_key",
        [
            pytest.param(
                "http://s3.localhost.localstack.cloud:4566/test-output-bucket-2/test-transcribe-job-e1895bdf.json?AWSAccessKeyId=000000000000&Signature=2Yc%2BvwhXx8UzmH8imzySfLOW6OI%3D&Expires=1688561914",
                "test-output-bucket-2",
                "test-transcribe-job-e1895bdf.json",
                id="output key as a single file",
            ),
            pytest.param(
                "http://s3.localhost.localstack.cloud:4566/test-output-bucket-5/test-files/test-output.json?AWSAccessKeyId=000000000000&Signature=F6bwF1M2N%2BLzEXTZnUtjE23S%2Bb0%3D&Expires=1688561920",
                "test-output-bucket-5",
                "test-files/test-output.json",
                id="output key with subdirectories",
            ),
            pytest.param(
                "http://s3.localhost.localstack.cloud:4566/test-output-bucket-2?AWSAccessKeyId=000000000000&Signature=2Yc%2BvwhXx8UzmH8imzySfLOW6OI%3D&Expires=1688561914",
                "test-output-bucket-2",
                "",
                id="output key as None",
            ),
        ],
    )
    def test_bucket_and_key_presign_url(
        self, presign_url, expected_output_bucket, expected_output_key
    ):
        bucket, key = s3_utils.get_bucket_and_key_from_presign_url(presign_url)
        assert bucket == expected_output_bucket
        assert key == expected_output_key

    @pytest.mark.parametrize(
        "header, dateobj, rule_id",
        [
            (
                'expiry-date="Sat, 15 Jul 2023 00:00:00 GMT", rule-id="rule1"',
                datetime.datetime(day=15, month=7, year=2023, tzinfo=zoneinfo.ZoneInfo(key="GMT")),
                "rule1",
            ),
            (
                'expiry-date="Mon, 29 Dec 2030 00:00:00 GMT", rule-id="rule2"',
                datetime.datetime(day=29, month=12, year=2030, tzinfo=zoneinfo.ZoneInfo(key="GMT")),
                "rule2",
            ),
            (
                'expiry-date="Tes, 32 Jul 2023 00:00:00 GMT", rule-id="rule3"',
                None,
                None,
            ),
            (
                'expiry="Sat, 15 Jul 2023 00:00:00 GMT", rule-id="rule4"',
                None,
                None,
            ),
            (
                'expiry-date="Sat, 15 Jul 2023 00:00:00 GMT"',
                None,
                None,
            ),
        ],
    )
    def test_parse_expiration_header(self, header, dateobj, rule_id):
        parsed_dateobj, parsed_rule_id = s3_utils.parse_expiration_header(header)
        assert parsed_dateobj == dateobj
        assert parsed_rule_id == rule_id

    @pytest.mark.parametrize(
        "rule_id, lifecycle_exp, last_modified, header",
        [
            (
                "rule1",
                {
                    "Date": datetime.datetime(
                        day=15, month=7, year=2023, tzinfo=zoneinfo.ZoneInfo(key="GMT")
                    )
                },
                datetime.datetime(
                    day=15,
                    month=9,
                    year=2024,
                    hour=0,
                    minute=0,
                    second=0,
                    microsecond=0,
                    tzinfo=None,
                ),
                'expiry-date="Sat, 15 Jul 2023 00:00:00 GMT", rule-id="rule1"',
            ),
            (
                "rule2",
                {"Days": 5},
                datetime.datetime(day=15, month=7, year=2023, tzinfo=None),
                'expiry-date="Fri, 21 Jul 2023 00:00:00 GMT", rule-id="rule2"',
            ),
            (
                "rule3",
                {"Days": 3},
                datetime.datetime(day=31, month=12, year=2030, microsecond=1, tzinfo=None),
                'expiry-date="Sat, 04 Jan 2031 00:00:00 GMT", rule-id="rule3"',
            ),
        ],
    )
    def test_serialize_expiration_header(self, rule_id, lifecycle_exp, last_modified, header):
        serialized_header = s3_utils.serialize_expiration_header(
            rule_id, lifecycle_exp, last_modified
        )
        assert serialized_header == header

    @pytest.mark.parametrize(
        "data, required, optional, result",
        [
            (
                {"field1": "", "field2": "", "field3": ""},
                {"field1"},
                {"field2", "field3"},
                True,
            ),
            (
                {"field1": ""},
                {"field1"},
                {"field2", "field3"},
                True,
            ),
            (
                {"field1": "", "field2": "", "field3": ""},  # field3 is not a field
                {"field1"},
                {"field2"},
                False,
            ),
            (
                {"field2": ""},  # missing field1
                {"field1"},
                {"field2"},
                False,
            ),
            (
                {"field3": ""},  # missing field1 and field3 is not a field
                {"field1"},
                {"field2"},
                False,
            ),
        ],
    )
    def test_validate_dict_fields(self, data, required, optional, result):
        assert s3_utils.validate_dict_fields(data, required, optional) == result

    @pytest.mark.parametrize(
        "tagging, result",
        [
            (
                "<Tagging><TagSet><Tag><Key>TagName</Key><Value>TagValue</Value></Tag></TagSet></Tagging>",
                {"TagName": "TagValue"},
            ),
            (
                "<Tagging><TagSet><Tag><Key>TagName</Key><Value>TagValue</Value></Tag><Tag><Key>TagName2</Key><Value>TagValue2</Value></Tag></TagSet></Tagging>",
                {"TagName": "TagValue", "TagName2": "TagValue2"},
            ),
            (
                "<InvalidXmlTagging></InvalidXmlTagging>",
                None,
            ),
        ],
        ids=["single", "list", "invalid"],
    )
    def test_parse_post_object_tagging_xml(self, tagging, result):
        assert s3_utils.parse_post_object_tagging_xml(tagging) == result

    def test_parse_post_object_tagging_xml_exception(self):
        with pytest.raises(MalformedXML) as e:
            s3_utils.parse_post_object_tagging_xml("not-xml")
        e.match(
            "The XML you provided was not well-formed or did not validate against our published schema"
        )

    @pytest.mark.parametrize(
        "s3_uri, bucket, object_key",
        [
            ("s3://test-bucket/key/test", "test-bucket", "key/test"),
            ("test-bucket/key/test", "test-bucket", "key/test"),
            ("s3://test-bucket", "test-bucket", ""),
            ("", "", ""),
            ("s3://test-bucket/test%2Ftest", "test-bucket", "test%2Ftest"),
        ],
    )
    def test_get_bucket_and_key_from_s3_uri(self, s3_uri, bucket, object_key):
        assert s3_utils.get_bucket_and_key_from_s3_uri(s3_uri) == (bucket, object_key)


class TestS3PresignedUrl:
    """
    Testing utils from the new Presigned URL validation with ASF
    """

    @staticmethod
    def _create_fake_context_from_path(path: str, method: str = "GET"):
        fake_context = RequestContext()
        fake_context.request = Request(
            method=method, path=path, query_string=urlparse(f"http://localhost{path}").query
        )
        return fake_context

    def test_is_presigned_url_request(self):
        request_paths = [
            (
                "GET",
                "/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test&X-Amz-Date=test&X-Amz-Expires=test&X-Amz-SignedHeaders=host&X-Amz-Signature=test",
                True,
            ),
            (
                "PUT",
                "/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test&X-Amz-Date=test&X-Amz-Expires=test&X-Amz-SignedHeaders=host&X-Amz-Signature=test",
                True,
            ),
            (
                "GET",
                "/?acl&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test&X-Amz-Date=test&X-Amz-Expires=test&X-Amz-SignedHeaders=host&X-Amz-Signature=test",
                True,
            ),
            (
                "GET",
                "/?acl&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=test&X-Amz-Expires=test&X-Amz-SignedHeaders=host&X-Amz-Signature=test",
                True,
            ),
            (
                "GET",
                "/?acl&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test&X-Amz-Date=testX-Amz-Expires=test&X-Amz-SignedHeaders=host",
                True,
            ),
            (
                "GET",
                "/?X-Amz-Credential=test&X-Amz-Date=testX-Amz-Expires=test&X-Amz-SignedHeaders=host&X-Amz-Signature=test",
                True,
            ),
            ("GET", "/?AWSAccessKeyId=test&Signature=test&Expires=test", True),
            ("GET", "/?acl&AWSAccessKeyId=test&Signature=test&Expires=test", True),
            ("GET", "/?acl&AWSAccessKey=test", False),
            ("GET", "/?acl", False),
            (
                "GET",
                "/?x-Amz-Credential=test&x-Amz-Date=testx-Amz-Expires=test&x-Amz-SignedHeaders=host&x-Amz-Signature=test",
                False,
            ),
        ]

        for method, request_path, expected_result in request_paths:
            fake_context = self._create_fake_context_from_path(path=request_path, method=method)
            assert (
                presigned_url.is_presigned_url_request(fake_context) == expected_result
            ), request_path

    def test_is_valid_presigned_url_v2(self):
        # structure: method, path, is_sig_v2, will_raise
        request_paths = [
            (
                "GET",
                "/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test&X-Amz-Date=test&X-Amz-Expires=test&X-Amz-SignedHeaders=host&X-Amz-Signature=test",
                False,
                False,
            ),
            ("GET", "/?acl", False, False),
            ("GET", "/?AWSAccessKeyId=test&Signature=test&Expires=test", True, False),
            ("GET", "/?acl&AWSAccessKeyId=test&Signature=test&Expires=test", True, False),
            ("GET", "/?acl&AWSAccessKey=test", False, False),
            ("GET", "/?acl&AWSAccessKeyId=test", False, True),
        ]

        for method, request_path, is_sig_v2, will_raise in request_paths:
            fake_context = self._create_fake_context_from_path(request_path, method)
            query_args = set(fake_context.request.args)
            if not will_raise:
                assert presigned_url.is_valid_sig_v2(query_args) == is_sig_v2
            else:
                with pytest.raises(Exception):
                    presigned_url.is_valid_sig_v2(query_args)

    def test_is_valid_presigned_url_v4(self):
        # structure: method, path, is_sig_v4, will_raise
        request_paths = [
            (
                "GET",
                "/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test&X-Amz-Date=test&X-Amz-Expires=test&X-Amz-SignedHeaders=host&X-Amz-Signature=test",
                True,
                False,
            ),
            ("GET", "/?acl", False, False),
            ("GET", "/?AWSAccessKeyId=test&Signature=test&Expires=test", False, False),
            (
                "GET",
                "/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test&X-Amz-Date=test&X-Amz-Expires=test&X-Amz-SignedHeaders=host&X-Amz-Signature=test",
                True,
                False,
            ),
            (
                "PUT",
                "/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test&X-Amz-Date=test&X-Amz-Expires=test&X-Amz-SignedHeaders=host&X-Amz-Signature=test",
                True,
                False,
            ),
            (
                "GET",
                "/?acl&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test&X-Amz-Date=test&X-Amz-Expires=test&X-Amz-SignedHeaders=host&X-Amz-Signature=test",
                True,
                False,
            ),
            (
                "GET",
                "/?acl&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=testX-Amz-Expires=test&X-Amz-SignedHeaders=host&X-Amz-Signature=test",
                True,
                True,
            ),
            (
                "GET",
                "/?acl&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test&X-Amz-Date=testX-Amz-Expires=test&X-Amz-SignedHeaders=host",
                True,
                True,
            ),
            (
                "GET",
                "/?X-Amz-Credential=test&X-Amz-Date=testX-Amz-Expires=test&X-Amz-SignedHeaders=host&X-Amz-Signature=test",
                True,
                True,
            ),
        ]

        for method, request_path, is_sig_v4, will_raise in request_paths:
            fake_context = self._create_fake_context_from_path(request_path, method)
            query_args = set(fake_context.request.args)
            if not will_raise:
                assert presigned_url.is_valid_sig_v4(query_args) == is_sig_v4
            else:
                with pytest.raises(Exception):
                    presigned_url.is_valid_sig_v4(query_args)


class TestS3AwsChunkedDecoder:
    """See https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html"""

    def test_s3_aws_chunked_decoder(self):
        body = "Hello\r\n\r\n\r\n\r\n"
        decoded_content_length = len(body)
        data = (
            "d;chunk-signature=af5e6c0a698b0192e9aa5d9083553d4d241d81f69ec62b184d05c509ad5166af\r\n"
            f"{body}\r\n0;chunk-signature=f2a50a8c0ad4d212b579c2489c6d122db88d8a0d0b987ea1f3e9d081074a5937\r\n"
        )

        stream = AwsChunkedDecoder(BytesIO(data.encode()), decoded_content_length)
        assert stream.read() == body.encode()

    def test_s3_aws_chunked_decoder_with_trailing_headers(self):
        body = "Hello Blob"
        decoded_content_length = len(body)

        data = (
            "a;chunk-signature=b5311ac60a88890e740a41e74f3d3b03179fd058b1e24bb3ab224042377c4ec9\r\n"
            f"{body}\r\n"
            "0;chunk-signature=78fae1c533e34dbaf2b83ad64ff02e4b64b7bc681ea76b6acf84acf1c48a83cb\r\n"
            f"x-amz-checksum-sha256:abcdef1234\r\n"
            "x-amz-trailer-signature:712fb67227583c88ac32f468fc30a249cf9ceeb0d0e947ea5e5209a10b99181c\r\n\r\n"
        )

        stream = AwsChunkedDecoder(BytesIO(data.encode()), decoded_content_length)
        assert stream.read() == body.encode()
        assert stream.trailing_headers == {
            "x-amz-checksum-sha256": "abcdef1234",
            "x-amz-trailer-signature": "712fb67227583c88ac32f468fc30a249cf9ceeb0d0e947ea5e5209a10b99181c",
        }

    def test_s3_aws_chunked_decoder_multiple_chunks(self):
        total_body = os.urandom(66560)
        decoded_content_length = len(total_body)
        chunk_size = 8192
        encoded_data = b""

        for index in range(0, decoded_content_length, chunk_size):
            chunk = total_body[index : min(index + chunk_size, decoded_content_length)]
            chunk_size_hex = str(hex(len(chunk)))[2:].encode()
            info_chunk = (
                chunk_size_hex
                + b";chunk-signature=af5e6c0a698b0192e9aa5d9083553d4d241d81f69ec62b184d05c509ad5166af\r\n"
            )
            encoded_data += info_chunk
            encoded_data += chunk + b"\r\n"

        encoded_data += b"0;chunk-signature=f2a50a8c0ad4d212b579c2489c6d122db88d8a0d0b987ea1f3e9d081074a5937\r\n"

        stream = AwsChunkedDecoder(BytesIO(encoded_data), decoded_content_length)
        assert stream.read() == total_body

        stream = AwsChunkedDecoder(BytesIO(encoded_data), decoded_content_length)
        # assert that even if we read more than a chunk size, we will get max chunk_size
        assert stream.read(chunk_size + 1000) == total_body[:chunk_size]
        # assert that even if we read more, when accessing the rest, we're still at the same position
        assert stream.read(10) == total_body[chunk_size : chunk_size + 10]

    def test_s3_aws_chunked_decoder_access_trailing(self):
        body = "Hello\r\n\r\n\r\n\r\n"
        decoded_content_length = len(body)
        data = (
            "d;chunk-signature=af5e6c0a698b0192e9aa5d9083553d4d241d81f69ec62b184d05c509ad5166af\r\n"
            f"{body}\r\n0;chunk-signature=f2a50a8c0ad4d212b579c2489c6d122db88d8a0d0b987ea1f3e9d081074a5937\r\n"
        )

        stream = AwsChunkedDecoder(BytesIO(data.encode()), decoded_content_length)
        with pytest.raises(AttributeError) as e:
            _ = stream.trailing_headers
        e.match("The stream has not been fully read yet, the trailing headers are not available.")

        stream.read()
        assert stream.trailing_headers == {}

    def test_s3_aws_chunked_decoder_chunk_bigger_than_s3_chunk(self):
        total_body = os.urandom(S3_CHUNK_SIZE * 2)
        decoded_content_length = len(total_body)
        chunk_size = S3_CHUNK_SIZE + 10
        encoded_data = b""

        for index in range(0, decoded_content_length, chunk_size):
            chunk = total_body[index : min(index + chunk_size, decoded_content_length)]
            chunk_size_hex = str(hex(len(chunk)))[2:].encode()
            info_chunk = (
                chunk_size_hex
                + b";chunk-signature=af5e6c0a698b0192e9aa5d9083553d4d241d81f69ec62b184d05c509ad5166af\r\n"
            )
            encoded_data += info_chunk
            encoded_data += chunk + b"\r\n"

        encoded_data += b"0;chunk-signature=f2a50a8c0ad4d212b579c2489c6d122db88d8a0d0b987ea1f3e9d081074a5937\r\n"

        stream = AwsChunkedDecoder(BytesIO(encoded_data), decoded_content_length)
        assert stream.read() == total_body

        stream = AwsChunkedDecoder(BytesIO(encoded_data), decoded_content_length)
        # assert that even if we read more than a chunk size, we will get max chunk_size
        assert stream.read(chunk_size + 1000) == total_body[:chunk_size]
        # assert that even if we read more, when accessing the rest, we're still at the same position
        assert stream.read(10) == total_body[chunk_size : chunk_size + 10]


class TestS3TemporaryStorageBackend:
    def test_get_fileobj_no_bucket(self, tmpdir):
        temp_storage_backend = EphemeralS3ObjectStore(root_directory=tmpdir)
        fake_object = S3Object(key="test-key")
        with temp_storage_backend.open("test-bucket", fake_object, mode="w") as s3_stored_object:
            s3_stored_object.write(BytesIO(b"abc"))

            assert s3_stored_object.read() == b"abc"

            s3_stored_object.seek(1)
            assert s3_stored_object.read() == b"bc"

            s3_stored_object.seek(0)
            assert s3_stored_object.read(1) == b"a"

            temp_storage_backend.remove("test-bucket", fake_object)
            assert s3_stored_object.file.closed

        temp_storage_backend.close()

    def test_ephemeral_multipart(self, tmpdir):
        temp_storage_backend = EphemeralS3ObjectStore(root_directory=tmpdir)
        fake_multipart = S3Multipart(key="test-multipart")

        s3_stored_multipart = temp_storage_backend.get_multipart("test-bucket", fake_multipart)
        parts = []
        stored_parts = []
        for i in range(1, 6):
            fake_s3_part = S3Part(part_number=i)
            with s3_stored_multipart.open(fake_s3_part, mode="w") as stored_part:
                stored_part.write(BytesIO(b"abc"))
                parts.append(fake_s3_part)
                stored_parts.append(stored_part)

        s3_stored_multipart.complete_multipart(parts=parts)
        temp_storage_backend.remove_multipart("test-bucket", fake_multipart)

        fake_object = S3Object(key="test-multipart")
        with temp_storage_backend.open(
            bucket="test-bucket", s3_object=fake_object, mode="r"
        ) as s3_stored_object:
            assert s3_stored_object.read() == b"abc" * 5

        assert all(stored_part.file.closed for stored_part in stored_parts)

        temp_storage_backend.close()
        assert s3_stored_object.file.closed

    def test_concurrent_file_access(self, tmpdir):
        temp_storage_backend = EphemeralS3ObjectStore(root_directory=tmpdir)
        fake_object = S3Object(key="test-key")

        with temp_storage_backend.open("test-bucket", fake_object, mode="w") as s3_object_writer:
            s3_object_writer.write(BytesIO(b"abc"))

        with (
            temp_storage_backend.open("test-bucket", fake_object, mode="r") as s3_stored_object_1,
            temp_storage_backend.open("test-bucket", fake_object, mode="r") as s3_stored_object_2,
        ):
            assert s3_stored_object_1.read() == b"abc"

            # assert that another StoredObject moving the position does not influence the other object
            s3_stored_object_1.seek(1)
            s3_stored_object_2.seek(2)
            assert s3_stored_object_1.read() == b"bc"
            assert s3_stored_object_2.read() == b"c"

            s3_stored_object_1.seek(0)
            assert s3_stored_object_1.read(1) == b"a"

            temp_storage_backend.remove("test-bucket", fake_object)
            assert s3_stored_object_1.file.closed
            assert s3_stored_object_2.file.closed

        temp_storage_backend.close()

    def test_s3_context_manager(self, tmpdir):
        temp_storage_backend = EphemeralS3ObjectStore(root_directory=tmpdir)
        fake_object = S3Object(key="test-key")
        s3_stored_object_1 = temp_storage_backend.open("test-bucket", fake_object, mode="w")
        s3_stored_object_1.write(BytesIO(b"abc"))
        s3_stored_object_1.close()
        # you can't call a context manager __enter__ on a closed S3 Object
        with pytest.raises(ValueError):
            with s3_stored_object_1:
                pass

        temp_storage_backend.close()
