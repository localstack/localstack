import unittest
from unittest import mock

from werkzeug.datastructures import Headers

from localstack.services.edge import HealthResource, get_auth_string, is_s3_form_data
from localstack.services.plugins import ServiceManager, ServiceState


class EdgeServiceTest(unittest.TestCase):
    def test_data_contains_key_equal_is_true(self):
        data_bytes = b"AWSAccessKeyId=someId&policy=somePolicy&key=someKey&signature=someSig"
        self.assertTrue(is_s3_form_data(data_bytes))

    def test_s3_form_data_is_true(self):
        data_bytes = b"""--28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="Content-Type"

        text/plain
        --28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="key"

        log.txt
        --28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="AWSAccessKeyId"

        AKIAIG7AH67ANH3GAWPQ
        --28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="policy"

        somePolicy
        --28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="signature"

        hTahNRfuCxL5HEKdhXxJPwvC6IQ=
        --28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="file"; filename="file"

        Hello World!
        --28f72589b2be0c9de84386b52c615990--
        """
        self.assertTrue(is_s3_form_data(data_bytes))

    def test_other_query_params_is_false(self):
        data_bytes = b"AWSAccessKeyId=someId&policy=somePolicy&param=value&signature=someSig"
        self.assertFalse(is_s3_form_data(data_bytes))

    def test_other_form_data_is_false(self):
        data_bytes = b"""--28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="AWSAccessKeyId"

        AKIAIG7AH67ANH3GAWPQ
        --28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="policy"

        somePolicy
        --28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="signature"

        hTahNRfuCxL5HEKdhXxJPwvC6IQ=
        --28f72589b2be0c9de84386b52c615990--
        """
        self.assertFalse(is_s3_form_data(data_bytes))

    def test_get_auth_string(self):
        # Typical Header with Authorization
        headers_with_auth = Headers(
            [
                ("X-Amz-Date", "20210313T160953Z"),
                (
                    "Authorization",
                    (
                        "AWS4-HMAC-SHA256 Credential="
                        "test/20210313/us-east-1/sqs/aws4_request, "
                        "SignedHeaders=content-type;host;x-amz-date, "
                        "Signature="
                        "3cba88ae6cbb8036126d2ba18ba8ded5"
                        "eea9e5484d70822affce9dad03be5993"
                    ),
                ),
            ]
        )

        body_with_auth = (
            b"X-Amz-Algorithm=AWS4-HMAC-SHA256&"
            + b"X-Amz-Credential="
            + b"test%2F20210313%2Fus-east-1%2Fsqs%2Faws4_request&"
            + b"X-Amz-Date=20210313T011059Z&"
            + b"X-Amz-Expires=86400000&"
            + b"X-Amz-SignedHeaders=content-type%3Bhost%3Bx-amz-date&"
            + b"X-Amz-Signature="
            + b"3cba88ae6cbb8036126d2ba18ba8ded5eea9e5484d70822affce9dad03be5993"
        )

        # check getting auth string from header with Authorization header
        self.assertEqual(
            headers_with_auth.get("authorization"),
            get_auth_string("POST", "/", headers_with_auth, b""),
        )

        # check getting auth string from body with authorization params
        self.assertEqual(
            headers_with_auth.get("authorization"),
            get_auth_string("POST", "/", Headers(), body_with_auth),
        )


class TestHealthResource:
    def test_put_and_get(self):
        service_manager = ServiceManager()
        service_manager.get_states = mock.MagicMock(return_value={"foo": ServiceState.AVAILABLE})

        resource = HealthResource(service_manager)

        resource.put(
            "/", b'{"features:initScripts": "initializing","features:persistence": "disabled"}'
        )

        state = resource.get("/", None)

        assert state == {
            "features": {
                "initScripts": "initializing",
                "persistence": "disabled",
            },
            "services": {
                "foo": "available",
            },
        }

    def test_put_overwrite_and_get(self):
        service_manager = ServiceManager()
        service_manager.get_states = mock.MagicMock(return_value={"foo": ServiceState.AVAILABLE})

        resource = HealthResource(service_manager)

        resource.put(
            "/", b'{"features:initScripts": "initializing","features:persistence": "disabled"}'
        )

        resource.put("/", b'{"features:initScripts": "initialized"}')

        state = resource.get("/", None)

        assert state == {
            "features": {
                "initScripts": "initialized",
                "persistence": "disabled",
            },
            "services": {
                "foo": "available",
            },
        }
