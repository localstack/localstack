import datetime
import unittest

import pytz
from requests.models import Response

from localstack.constants import LOCALHOST, S3_VIRTUAL_HOSTNAME
from localstack.services.infra import patch_instance_tracker_meta
from localstack.services.s3 import multipart_content, s3_listener, s3_starter, s3_utils
from localstack.services.s3.s3_listener import s3_global_backend
from localstack.services.s3.s3_utils import get_key_from_s3_url
from localstack.utils.strings import short_uid


class S3ListenerTest(unittest.TestCase):
    def test_expand_redirect_url(self):
        url1 = s3_listener.expand_redirect_url("http://example.org", "K", "B")
        self.assertEqual("http://example.org?key=K&bucket=B", url1)

        url2 = s3_listener.expand_redirect_url("http://example.org/?id=I", "K", "B")
        self.assertEqual("http://example.org/?id=I&key=K&bucket=B", url2)

    def test_find_multipart_key_value(self):
        headers = {
            "Host": "10.0.1.19:4572",
            "User-Agent": "curl/7.51.0",
            "Accept": "*/*",
            "Content-Length": "992",
            "Expect": "100-continue",
            "Content-Type": "multipart/form-data; boundary=------------------------3c48c744237517ac",
        }

        data1 = (
            b'--------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="key"\r\n\r\n'
            b"uploads/20170826T181315.679087009Z/upload/pixel.png\r\n--------------------------3c48c744237517ac"
            b'\r\nContent-Disposition: form-data; name="success_action_redirect"\r\n\r\nhttp://127.0.0.1:5000/'
            b"?id=20170826T181315.679087009Z\r\n--------------------------3c48c744237517ac--\r\n"
        )

        data2 = (
            b'--------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="key"\r\n\r\n'
            b"uploads/20170826T181315.679087009Z/upload/pixel.png\r\n--------------------------3c48c744237517ac"
            b"--\r\n"
        )

        data3 = (
            b'--------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="success_action_'
            b'redirect"\r\n\r\nhttp://127.0.0.1:5000/?id=20170826T181315.679087009Z\r\n--------------------------'
            b"3c48c744237517ac--\r\n"
        )

        data4 = (
            b'--------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="key"\r\n\r\n'
            b"uploads/20170826T181315.679087009Z/upload/pixel.png\r\n--------------------------3c48c744237517ac"
            b'\r\nContent-Disposition: form-data; name="success_action_status"\r\n\r\n201'
            b"\r\n--------------------------3c48c744237517ac--\r\n"
        )

        key1, url1 = multipart_content.find_multipart_key_value(data1, headers)

        self.assertEqual("uploads/20170826T181315.679087009Z/upload/pixel.png", key1)
        self.assertEqual("http://127.0.0.1:5000/?id=20170826T181315.679087009Z", url1)

        key2, url2 = multipart_content.find_multipart_key_value(data2, headers)

        self.assertEqual("uploads/20170826T181315.679087009Z/upload/pixel.png", key2)
        self.assertIsNone(url2, "Should not get a redirect URL without success_action_redirect")

        key3, url3 = multipart_content.find_multipart_key_value(data3, headers)

        self.assertIsNone(key3, "Should not get a key without provided key")
        self.assertIsNone(url3, "Should not get a redirect URL without provided key")

        key4, status_code = multipart_content.find_multipart_key_value(
            data4, headers, "success_action_status"
        )

        self.assertEqual("uploads/20170826T181315.679087009Z/upload/pixel.png", key4)
        self.assertEqual("201", status_code)

    def test_expand_multipart_filename(self):
        headers = {
            "Host": "10.0.1.19:4572",
            "User-Agent": "curl/7.51.0",
            "Accept": "*/*",
            "Content-Length": "992",
            "Expect": "100-continue",
            "Content-Type": "multipart/form-data; boundary=------------------------3c48c744237517ac",
        }

        data1 = (
            b'--------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="key"\r\n\r\n'
            b"uploads/20170826T181315.679087009Z/upload/${filename}\r\n--------------------------3c48c744237517ac"
            b'\r\nContent-Disposition: form-data; name="AWSAccessKeyId"\r\n\r\nWHAT\r\n--------------------------'
            b'3c48c744237517ac\r\nContent-Disposition: form-data; name="policy"\r\n\r\nNO\r\n--------------------'
            b'------3c48c744237517ac\r\nContent-Disposition: form-data; name="signature"\r\n\r\nYUP\r\n----------'
            b'----------------3c48c744237517ac\r\nContent-Disposition: form-data; name="acl"\r\n\r\nprivate\r\n--'
            b'------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="success_action_re'
            b'direct"\r\n\r\nhttp://127.0.0.1:5000/\r\n--------------------------3c48c744237517ac\r\nContent-Disp'
            b'osition: form-data; name="file"; filename="pixel.png"\r\nContent-Type: application/octet-stream\r\n'
            b"\r\n\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15"
            b"\xc4\x89\x00\x00\x00\x19tEXtSoftware\x00Adobe ImageReadyq\xc9e<\x00\x00\x00\x0eIDATx\xdabb\x00\x02"
            b"\x80\x00\x03\x00\x00\x0f\x00\x03`|\xce\xe9\x00\x00\x00\x00IEND\xaeB`\x82\r\n-----------------------"
            b"---3c48c744237517ac--\r\n"
        )

        data2 = (
            b'--------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="key"\r\n\r\n'
            b"uploads/20170826T181315.679087009Z/upload/pixel.png\r\n--------------------------3c48c744237517ac"
            b'\r\nContent-Disposition: form-data; name="AWSAccessKeyId"\r\n\r\nWHAT\r\n--------------------------'
            b'3c48c744237517ac\r\nContent-Disposition: form-data; name="policy"\r\n\r\nNO\r\n--------------------'
            b'------3c48c744237517ac\r\nContent-Disposition: form-data; name="signature"\r\n\r\nYUP\r\n----------'
            b'----------------3c48c744237517ac\r\nContent-Disposition: form-data; name="acl"\r\n\r\nprivate\r\n--'
            b'------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="success_action_re'
            b'direct"\r\n\r\nhttp://127.0.0.1:5000/\r\n--------------------------3c48c744237517ac\r\nContent-Disp'
            b'osition: form-data; name="file"; filename="pixel.png"\r\nContent-Type: application/octet-stream\r\n'
            b"\r\n\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15"
            b"\xc4\x89\x00\x00\x00\x19tEXtSoftware\x00Adobe ImageReadyq\xc9e<\x00\x00\x00\x0eIDATx\xdabb\x00\x02"
            b"\x80\x00\x03\x00\x00\x0f\x00\x03`|\xce\xe9\x00\x00\x00\x00IEND\xaeB`\x82\r\n-----------------------"
            b"---3c48c744237517ac--\r\n"
        )

        data3 = (
            '--------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="key"\r\n\r\n'
            "uploads/20170826T181315.679087009Z/upload/${filename}\r\n--------------------------3c48c744237517ac"
            '\r\nContent-Disposition: form-data; name="AWSAccessKeyId"\r\n\r\nWHAT\r\n--------------------------'
            '3c48c744237517ac\r\nContent-Disposition: form-data; name="policy"\r\n\r\nNO\r\n--------------------'
            '------3c48c744237517ac\r\nContent-Disposition: form-data; name="signature"\r\n\r\nYUP\r\n----------'
            '----------------3c48c744237517ac\r\nContent-Disposition: form-data; name="acl"\r\n\r\nprivate\r\n--'
            '------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="success_action_re'
            'direct"\r\n\r\nhttp://127.0.0.1:5000/\r\n--------------------------3c48c744237517ac\r\nContent-Disp'
            'osition: form-data; name="file"; filename="pixel.txt"\r\nContent-Type: text/plain\r\n\r\nHello World'
            "\r\n--------------------------3c48c744237517ac--\r\n"
        )

        expanded1 = multipart_content.expand_multipart_filename(data1, headers)
        self.assertIsNot(
            expanded1,
            data1,
            "Should have changed content of data with filename to interpolate",
        )
        self.assertIn(
            b"uploads/20170826T181315.679087009Z/upload/pixel.png",
            expanded1,
            "Should see the interpolated filename",
        )

        expanded2 = multipart_content.expand_multipart_filename(data2, headers)
        self.assertIs(
            expanded2,
            data2,
            "Should not have changed content of data with no filename to interpolate",
        )

        expanded3 = multipart_content.expand_multipart_filename(data3, headers)
        self.assertIsNot(
            expanded3,
            data3,
            "Should have changed content of string data with filename to interpolate",
        )
        self.assertIn(
            b"uploads/20170826T181315.679087009Z/upload/pixel.txt",
            expanded3,
            "Should see the interpolated filename",
        )

    def test_event_type_matching(self):
        match = s3_listener.event_type_matches
        self.assertTrue(match(["s3:ObjectCreated:*"], "ObjectCreated", "Put"))
        self.assertTrue(match(["s3:ObjectCreated:*"], "ObjectCreated", "Post"))
        self.assertTrue(match(["s3:ObjectCreated:Post"], "ObjectCreated", "Post"))
        self.assertTrue(match(["s3:ObjectDeleted:*"], "ObjectDeleted", "Delete"))
        self.assertFalse(match(["s3:ObjectCreated:Post"], "ObjectCreated", "Put"))
        self.assertFalse(match(["s3:ObjectCreated:Post"], "ObjectDeleted", "Put"))

    def test_is_query_allowable(self):
        self.assertTrue(s3_listener.ProxyListenerS3.is_query_allowable("POST", "uploadId"))
        self.assertTrue(s3_listener.ProxyListenerS3.is_query_allowable("POST", ""))
        self.assertTrue(s3_listener.ProxyListenerS3.is_query_allowable("PUT", ""))
        self.assertFalse(
            s3_listener.ProxyListenerS3.is_query_allowable("POST", "differentQueryString")
        )
        # abort multipart upload is a delete with the same query string as a complete multipart upload
        self.assertFalse(s3_listener.ProxyListenerS3.is_query_allowable("DELETE", "uploadId"))
        self.assertFalse(
            s3_listener.ProxyListenerS3.is_query_allowable("DELETE", "differentQueryString")
        )
        self.assertFalse(s3_listener.ProxyListenerS3.is_query_allowable("PUT", "uploadId"))

    def test_append_last_modified_headers(self):
        xml_with_last_modified = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            "  <Name>thanos/Name>"
            "  <Contents>"
            "    <LastModified>2019-05-27T19:00:16.663Z</LastModified>"
            "  </Contents>"
            "</ListBucketResult>"
        )
        xml_without_last_modified = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            "  <Name>thanos/Name>"
            "  <Contents>"
            "    <NotLastModified>2019-05-27T19:00:16.663Z</NotLastModified>"
            "  </Contents>"
            "</ListBucketResult>"
        )

        # if there is a parsable date in XML <LastModified>, use it
        response = Response()
        s3_listener.append_last_modified_headers(response, content=xml_with_last_modified)
        self.assertEqual("Mon, 27 May 2019 19:00:16 GMT", response.headers.get("Last-Modified", ""))

        # otherwise, just fill the header with the currentdate
        # I will not test currentDate as it is not trivial without adding dependencies
        # so, I'm testing for the presence of the header only
        response = Response()
        s3_listener.append_last_modified_headers(response, content=xml_without_last_modified)
        self.assertNotEqual("No header", response.headers.get("Last-Modified", "No header"))

        response = Response()
        s3_listener.append_last_modified_headers(response)
        self.assertNotEqual("No header", response.headers.get("Last-Modified", "No header"))


class TestS3Utils:
    def test_s3_bucket_name(self):
        # array description : 'bucket_name', 'expected_ouput'
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
            assert s3_utils.validate_bucket_name(bucket_name) == expected_result

    def test_is_expired(self):
        offset = datetime.timedelta(seconds=5)
        assert s3_utils.is_expired(datetime.datetime.now() - offset)
        assert not s3_utils.is_expired(datetime.datetime.now() + offset)

    def test_is_expired_with_tz(self):
        offset = datetime.timedelta(seconds=5)
        assert s3_utils.is_expired(datetime.datetime.now(tz=pytz.timezone("EST")) - offset)
        assert not s3_utils.is_expired(datetime.datetime.now(tz=pytz.timezone("EST")) + offset)

    def test_bucket_name(self):
        # array description : 'path', 'header', 'expected_ouput'
        bucket_names = [
            ("/bucket/keyname", {"host": f"https://{LOCALHOST}:4566"}, "bucket"),
            ("/bucket//keyname", {"host": f"https://{LOCALHOST}:4566"}, "bucket"),
            ("/keyname", {"host": f"bucket.{S3_VIRTUAL_HOSTNAME}:4566"}, "bucket"),
            ("//keyname", {"host": f"bucket.{S3_VIRTUAL_HOSTNAME}:4566"}, "bucket"),
            ("/", {"host": f"{S3_VIRTUAL_HOSTNAME}:4566"}, None),
            ("/", {"host": "bucket.s3-ap-northeast-1.amazonaws.com:4566"}, "bucket"),
            ("/", {"host": "bucket.s3-ap-northeast-2.amazonaws.com:4566"}, "bucket"),
            ("/", {"host": "bucket.s3-ap-south-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3-ap-southeast-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3-ap-southeast-2.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3-ca-central-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3-eu-central-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "http://bucket.s3-eu-west-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "http://bucket.s3-eu-west-2.amazonaws.com"}, "bucket"),
            ("/", {"host": "http://bucket.s3-eu-west-3.amazonaws.com"}, "bucket"),
            ("/", {"host": "http://bucket.s3-external-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "http://bucket.s3-sa-east-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3-us-east-2.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3-us-west-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3-us-west-2.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.ap-northeast-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.ap-northeast-2.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.ap-south-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.ap-southeast-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.ap-southeast-2.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.ca-central-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.cn-north-1.amazonaws.com.cn"}, "bucket"),
            ("/", {"host": "bucket.s3.cn-northwest-1.amazonaws.com.cn"}, "bucket"),
            (
                "/",
                {"host": "bucket.s3.dualstack.ap-northeast-1.amazonaws.com"},
                "bucket",
            ),
            (
                "/",
                {"host": "https://bucket.s3.dualstack.ap-northeast-2.amazonaws.com"},
                "bucket",
            ),
            (
                "/",
                {"host": "https://bucket.s3.dualstack.ap-south-1.amazonaws.com"},
                "bucket",
            ),
            (
                "/",
                {"host": "https://bucket.s3.dualstack.ap-southeast-1.amazonaws.com"},
                "bucket",
            ),
            (
                "/",
                {"host": "https://bucket.s3.dualstack.ap-southeast-2.amazonaws.com"},
                "bucket",
            ),
            (
                "/",
                {"host": "https://bucket.s3.dualstack.ca-central-1.amazonaws.com"},
                "bucket",
            ),
            (
                "/",
                {"host": "https://bucket.s3.dualstack.eu-central-1.amazonaws.com"},
                "bucket",
            ),
            ("/", {"host": "bucket.s3.dualstack.eu-west-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.dualstack.eu-west-2.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.dualstack.eu-west-3.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.dualstack.sa-east-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.dualstack.us-east-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.dualstack.us-east-2.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.dualstack.us-west-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.dualstack.us-west-2.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.eu-central-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.eu-west-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.eu-west-2.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.eu-west-3.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.sa-east-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.us-east-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.us-east-2.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.us-west-1.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.us-west-2.amazonaws.com"}, "bucket"),
            ("/", {"host": "bucket.s3.localhost.localstack.cloud"}, "bucket"),
            (
                "/",
                {"host": "bucket-1.s3-website.localhost.localstack.cloud"},
                "bucket-1",
            ),
            (
                "/",
                {"host": "bucket.localhost.localstack.cloud"},
                "bucket",
            ),  # internally agreed upon special case
            ("/", {"host": "localhost.localstack.cloud"}, None),
            ("/", {"host": "test.dynamodb.amazonaws.com"}, None),
            ("/", {"host": "dynamodb.amazonaws.com"}, None),
        ]

        for path, headers, expected_result in bucket_names:
            assert s3_utils.extract_bucket_name(headers, path) == expected_result

    # test whether method correctly distinguishes between hosted and path style bucket references
    # path style format example: https://s3.{region}.localhost.localstack.cloud:4566/{bucket-name}/{key-name}
    # hosted style format example: http://aws.s3.localhost.localstack.cloud:4566/
    def test_uses_host_address(self):
        addresses = [
            ({"host": f"https://aws.{LOCALHOST}:4566"}, False),
            # attention: This is **not** a host style reference according to s3 specs but a special case from our side
            ({"host": f"https://aws.{LOCALHOST}.localstack.cloud:4566"}, True),
            ({"host": f"https://{LOCALHOST}.aws:4566"}, False),
            ({"host": f"https://{LOCALHOST}.swa:4566"}, False),
            ({"host": f"https://swa.{LOCALHOST}:4566"}, False),
            ({"host": "https://bucket.s3.localhost.localstack.cloud"}, True),
            ({"host": "bucket.s3.eu-west-1.amazonaws.com"}, True),
            ({"host": "https://s3.eu-west-1.localhost.localstack.cloud/bucket"}, False),
            ({"host": "https://s3.eu-west-1.localhost.localstack.cloud/bucket/key"}, False),
            ({"host": "https://s3.localhost.localstack.cloud/bucket"}, False),
            ({"host": "https://bucket.s3.eu-west-1.localhost.localstack.cloud/key"}, True),
            (
                {
                    "host": "https://bucket.s3.eu-west-1.localhost.localstack.cloud/key/key/content.png"
                },
                True,
            ),
            ({"host": "https://s3.localhost.localstack.cloud/bucket/key"}, False),
            ({"host": "https://bucket.s3.eu-west-1.localhost.localstack.cloud"}, True),
            ({"host": "https://bucket.s3.localhost.localstack.cloud/key"}, True),
            ({"host": "bucket.s3.eu-west-1.amazonaws.com"}, True),
            ({"host": "bucket.s3.amazonaws.com"}, True),
            ({"host": "notabucket.amazonaws.com"}, False),
            ({"host": "s3.amazonaws.com"}, False),
            ({"host": "s3.eu-west-1.amazonaws.com"}, False),
        ]
        for headers, expected_result in addresses:
            assert s3_utils.uses_host_addressing(headers) == expected_result

    def test_s3_keyname_name(self):
        # array description : 'path', 'header', 'expected_ouput'
        key_names = [
            ("/bucket/keyname", {"host": f"https://{LOCALHOST}:4566"}, "keyname"),
            ("/bucket//keyname", {"host": f"https://{LOCALHOST}:4566"}, "/keyname"),
            (
                "/keyname",
                {"host": f"https://bucket.{S3_VIRTUAL_HOSTNAME}:4566"},
                "keyname",
            ),
            (
                "//keyname",
                {"host": f"https://bucket.{S3_VIRTUAL_HOSTNAME}:4566"},
                "/keyname",
            ),
        ]

        for path, headers, expected_result in key_names:
            assert s3_utils.extract_key_name(headers, path) == expected_result

    def test_get_key_from_s3_url(self):
        for prefix in ["s3://test-bucket/", "", "/"]:
            for slash_prefix in [True, False]:
                for key in ["my/key/123", "/mykey"]:
                    url = f"{prefix}{key}"
                    expected = f"{'/' if slash_prefix else ''}{key.lstrip('/')}"
                    assert get_key_from_s3_url(url, leading_slash=slash_prefix) == expected


class S3BackendTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        s3_starter.apply_patches()
        patch_instance_tracker_meta()

    def test_key_instances_before_removing(self):
        s3_backend = s3_global_backend()

        bucket_name = "test"
        region = "us-east-1"

        file1_name = "file.txt"
        file2_name = "file2.txt"
        file_value = b"content"

        s3_backend.create_bucket(bucket_name, region)
        s3_backend.put_object(bucket_name, file1_name, file_value)
        s3_backend.put_object(bucket_name, file2_name, file_value)

        key = s3_backend.get_object(bucket_name, file2_name)

        self.assertNotIn(key, key.instances or [])

    def test_no_bucket_in_instances(self):
        s3_backend = s3_global_backend()

        bucket_name = f"b-{short_uid()}"
        region = "us-east-1"

        s3_backend.create_bucket(bucket_name, region)

        s3_backend.delete_bucket(bucket_name)
        bucket = s3_backend.create_bucket(bucket_name, region)

        self.assertNotIn(bucket, (bucket.instances or []))
