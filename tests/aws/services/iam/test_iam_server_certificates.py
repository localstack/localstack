"""
Tests for IAM Server Certificate operations.

Migrated from moto's test suite to LocalStack with snapshot testing for AWS parity validation.
"""

import logging

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)

# TODO remove after new IAM implementation of server certificates
pytestmark = pytest.mark.skip

# Sample certificate and private key for testing
# These are valid PEM-encoded certificates that AWS will accept
SAMPLE_CERT_BODY = """-----BEGIN CERTIFICATE-----
MIIEHTCCAwWgAwIBAgIDAJojMA0GCSqGSIb3DQEBCwUAMIGLMQswCQYDVQQGEwJV
UzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEX
MBUGA1UECgwOTXlPcmdhbml6YXRpb24xHTAbBgNVBAsMFE15T3JnYW5pemF0aW9u
YWxVbml0MRcwFQYDVQQDDA5NeSBvd24gUm9vdCBDQTAeFw0yMTAzMTExNTAwNDla
Fw0zMDAzMDkxNTAwNDlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZv
cm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEXMBUGA1UECgwOTXlPcmdhbml6
YXRpb24xHTAbBgNVBAsMFE15T3JnYW5pemF0aW9uYWxVbml0MRQwEgYDVQQDDAtl
eGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnKQhQG
pRuxcO5RF8VMyAmWe4rs4XWeodVQflYtJVY+mCg/JidmgYe1EYXvE2Qqf1Xzi2O2
oEJJSAs/s+Wb91yzunnoHVR/5uTHdjN2e6HRhEmUFlJuconjlmBxVKe1LG4Ra8yr
JA+E0tS2kzrGCLNcFpghQ982GJjuvRWm9nAAsCJPm7N8a/Gm1opMdUkiH1b/3d47
0wugisz6fYRHQ61UIYfjNUWlg/tV1thGOScAB2RyusQJdTB422BQAlpD4TTX8uj8
Wd0GhYjpM8DWWpSUOFsoYOHBc3bPr7ctpOoIG8gZcs56zDwZi9CVda4viS/8HPnC
r8jXaQW1pqwP8ekCAwEAAaOBijCBhzAJBgNVHRMEAjAAMB0GA1UdDgQWBBTaOaPu
XmtLDTJVv++VYBiQr9gHCTAfBgNVHSMEGDAWgBTaOaPuXmtLDTJVv++VYBiQr9gH
CTATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCB4AwGAYDVR0RBBEwD4IN
Ki5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAWIZu4sma7MmWTXSMwKSP
stQDWdIvcwthD8ozHkLsNdl5eKqOEndAc0wb7mSk1z8rRkSsd0D0T2zaKyduCYrs
eBAMhS2+NnHWcXxhn0VOkmXhw5kO8Un14KIptRH0y8FIqHMJ8LrSiK9g9fWCRlI9
g7eBipu43hzGyMiBP3K0EQ4m49QXlIEwG3OIWak5hdR29h3cD6xXMXaUtlOswsAN
3PDG/gcjZWZpkwPlaVzwjV8MRsYLmQIYdHPr/qF1FWddYPvK89T0nzpgiuFdBOTY
W6I1TeTAXFXG2Qf4trXsh5vsFNAisxlRF3mkpixYP5OmVXTOyN7cCOSPOUh6Uctv
eg==
-----END CERTIFICATE-----"""

SAMPLE_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJykIUBqUbsXDu
URfFTMgJlnuK7OF1nqHVUH5WLSVWPpgoPyYnZoGHtRGF7xNkKn9V84tjtqBCSUgL
P7Plm/dcs7p56B1Uf+bkx3Yzdnuh0YRJlBZSbnKJ45ZgcVSntSxuEWvMqyQPhNLU
tpM6xgizXBaYIUPfNhiY7r0VpvZwALAiT5uzfGvxptaKTHVJIh9W/93eO9MLoIrM
+n2ER0OtVCGH4zVFpYP7VdbYRjknAAdkcrrECXUweNtgUAJaQ+E01/Lo/FndBoWI
6TPA1lqUlDhbKGDhwXN2z6+3LaTqCBvIGXLOesw8GYvQlXWuL4kv/Bz5wq/I12kF
taasD/HpAgMBAAECggEAKePgBdI/UllqrT6OZboDyOHBcdytDULKK8NTBsbGenny
EmDRpdpEx4xSP/CaoO+lkY1GgYO3DyuxVgx6Zw8Ssd7ptkb2V8VZhGLX6eUN01Dw
WmnwnForUu65F/pO7aXRvGPHciyRBtu2/MuOEuRrh/h1BE3bjinnv0/IVwdbH3LW
pLiJoxzlSJDDomaIAOtB3u6Lw1/6kXiYT9lvXnUpBzR+1uMApTPQN0NJuxLiA0Rs
es2kBTZ/weEQW+GeJaSYmEXX9zCKGMVCq5EZfS3sH0TrkDENVqW40J+OF3Ee6r12
CoWLWkC+DPtfHvwh1zp89HFYZ7I6lyycBb31yHb1kQKBgQDuURbpgWxP7XaSgPuI
6rv2ApjZQav58kNj1K1pRIcnoZsfz3LX3xfft0PKyoKDmndN8nS9KKL9T//XIBaO
PeD3XzlSvQQ/SvNdaBHqOzkkwldGng3swR3c8RELoaKU9yBdhlMFYXkZsIp5hZgG
MPVdihamFfUk9J/sdYAr9vjnVQKBgQDYw1TWyBi4UTkMox62hqSUgWw3llaliHkP
tEinMKF3i0oZzGzWDIHV9YoPPuu2L5cy+j2wLe8r6DWvsKd0dqeNS/yXYj7eIDVz
fff9SmP25RdtV8h6fkAiLD708G7P0w94G+LhakuVpeTpMNSDPWUk6bl+K81ZRvm6
DKS7aOM4RQKBgEhQFrG38dO27Fm8BZcgEvStCRAzWym2lzg9mnjssE4YPWfDnMdg
DHB3vXxVQpEIV9cxELctE3flxG3UcMOshwzIui4e6KED7yCSqYz3d3lt9umYoAUM
/DDEfTWYUCr/abS3Q43Ia+SdqwcAwIZwaKN/eSvgUchq6fPoG4I7qH8ZAoGBAMRS
ndtuHZ2Kyw3cC6wrZJKwabAq9M02PtdvZMIwdH3OZU3abdSsPUfo/KL0TQ6UKfBc
31RbNhzhUwaODAyajwSVhvAhZmlOaLryo5IAN2vdcAtzjzsKb9HDmz3DKcoHEiKp
tyKMYGrodtyRglhfWeVF3uAckf9DHllYrDalN+61AoGAP9OrCgoDnjtTasFzibZ8
jb+xYG9E42smB2gep03Jj8l5gqnWTFh0TyA1Z7+RJNvSzkqK8bU/uAH/TgJAqviE
7XA7a2yuaf/Ww4vToy5bo1HqhQBak1PP2wzuWiUkJcyTRTGryLvnIR9fDonJ9TAd
0GsjqdfyAqjsvycLNvwR0wk=
-----END PRIVATE KEY-----"""

# Sample certificate chain (same as the cert for simplicity in testing)
SAMPLE_CERT_CHAIN = """-----BEGIN CERTIFICATE-----
MIIEHTCCAwWgAwIBAgIDAJojMA0GCSqGSIb3DQEBCwUAMIGLMQswCQYDVQQGEwJV
UzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEX
MBUGA1UECgwOTXlPcmdhbml6YXRpb24xHTAbBgNVBAsMFE15T3JnYW5pemF0aW9u
YWxVbml0MRcwFQYDVQQDDA5NeSBvd24gUm9vdCBDQTAeFw0yMTAzMTExNTAwNDla
Fw0zMDAzMDkxNTAwNDlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZv
cm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEXMBUGA1UECgwOTXlPcmdhbml6
YXRpb24xHTAbBgNVBAsMFE15T3JnYW5pemF0aW9uYWxVbml0MRQwEgYDVQQDDAtl
eGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnKQhQG
pRuxcO5RF8VMyAmWe4rs4XWeodVQflYtJVY+mCg/JidmgYe1EYXvE2Qqf1Xzi2O2
oEJJSAs/s+Wb91yzunnoHVR/5uTHdjN2e6HRhEmUFlJuconjlmBxVKe1LG4Ra8yr
JA+E0tS2kzrGCLNcFpghQ982GJjuvRWm9nAAsCJPm7N8a/Gm1opMdUkiH1b/3d47
0wugisz6fYRHQ61UIYfjNUWlg/tV1thGOScAB2RyusQJdTB422BQAlpD4TTX8uj8
Wd0GhYjpM8DWWpSUOFsoYOHBc3bPr7ctpOoIG8gZcs56zDwZi9CVda4viS/8HPnC
r8jXaQW1pqwP8ekCAwEAAaOBijCBhzAJBgNVHRMEAjAAMB0GA1UdDgQWBBTaOaPu
XmtLDTJVv++VYBiQr9gHCTAfBgNVHSMEGDAWgBTaOaPuXmtLDTJVv++VYBiQr9gH
CTATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCB4AwGAYDVR0RBBEwD4IN
Ki5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAWIZu4sma7MmWTXSMwKSP
stQDWdIvcwthD8ozHkLsNdl5eKqOEndAc0wb7mSk1z8rRkSsd0D0T2zaKyduCYrs
eBAMhS2+NnHWcXxhn0VOkmXhw5kO8Un14KIptRH0y8FIqHMJ8LrSiK9g9fWCRlI9
g7eBipu43hzGyMiBP3K0EQ4m49QXlIEwG3OIWak5hdR29h3cD6xXMXaUtlOswsAN
3PDG/gcjZWZpkwPlaVzwjV8MRsYLmQIYdHPr/qF1FWddYPvK89T0nzpgiuFdBOTY
W6I1TeTAXFXG2Qf4trXsh5vsFNAisxlRF3mkpixYP5OmVXTOyN7cCOSPOUh6Uctv
eg==
-----END CERTIFICATE-----"""


@pytest.fixture(autouse=True)
def snapshot_transformers(snapshot):
    snapshot.add_transformers_list(snapshot.transform.iam_api())
    snapshot.add_transformer(snapshot.transform.key_value("ServerCertificateId"))
    snapshot.add_transformer(snapshot.transform.key_value("CertificateBody"))
    snapshot.add_transformer(snapshot.transform.key_value("CertificateChain"))


@pytest.fixture
def upload_server_certificate(aws_client):
    """Factory fixture to upload server certificates with automatic cleanup."""
    created_certs = []

    def _upload_cert(cert_name=None, cert_body=None, private_key=None, cert_chain=None, path=None):
        if cert_name is None:
            cert_name = f"cert-{short_uid()}"
        if cert_body is None:
            cert_body = SAMPLE_CERT_BODY
        if private_key is None:
            private_key = SAMPLE_PRIVATE_KEY

        kwargs = {
            "ServerCertificateName": cert_name,
            "CertificateBody": cert_body,
            "PrivateKey": private_key,
        }
        if cert_chain is not None:
            kwargs["CertificateChain"] = cert_chain
        if path is not None:
            kwargs["Path"] = path

        response = aws_client.iam.upload_server_certificate(**kwargs)
        created_certs.append(cert_name)
        return response

    yield _upload_cert

    # Cleanup
    for cert_name in created_certs:
        try:
            aws_client.iam.delete_server_certificate(ServerCertificateName=cert_name)
        except ClientError as e:
            LOG.debug("Could not delete server certificate %s during cleanup: %s", cert_name, e)


class TestServerCertificate:
    """Tests for server certificate operations."""

    @markers.aws.validated
    @pytest.mark.parametrize("path", [None, "/", "/test-path/"])
    def test_server_certificate_lifecycle(
        self, aws_client, snapshot, upload_server_certificate, path
    ):
        """Test upload, list, get, and delete server certificate operations."""
        cert_name = f"cert-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.key_value("ServerCertificateName"))
        if path:
            snapshot.add_transformer(snapshot.transform.regex(path, "/<path>/"))

        # Upload server certificate
        kwargs = {}
        if path is not None:
            kwargs["Path"] = path
        upload_response = aws_client.iam.upload_server_certificate(
            ServerCertificateName=cert_name,
            CertificateBody=SAMPLE_CERT_BODY,
            PrivateKey=SAMPLE_PRIVATE_KEY,
            **kwargs,
        )
        snapshot.match("upload-certificate", upload_response)

        # List server certificates
        list_response = aws_client.iam.list_server_certificates()
        list_response["ServerCertificateMetadataList"] = [
            c
            for c in list_response["ServerCertificateMetadataList"]
            if c["ServerCertificateName"] == cert_name
        ]
        snapshot.match("list-certificates", list_response)

        # List with path prefix (if path specified)
        if path not in [None, "/"]:
            list_with_path = aws_client.iam.list_server_certificates(PathPrefix=path)
            list_with_path["ServerCertificateMetadataList"] = [
                c
                for c in list_with_path["ServerCertificateMetadataList"]
                if c["ServerCertificateName"] == cert_name
            ]
            snapshot.match("list-certificates-with-path", list_with_path)

        # Get server certificate
        get_response = aws_client.iam.get_server_certificate(ServerCertificateName=cert_name)
        snapshot.match("get-certificate", get_response)

        # Delete server certificate
        delete_response = aws_client.iam.delete_server_certificate(ServerCertificateName=cert_name)
        snapshot.match("delete-certificate", delete_response)

        # Verify certificate no longer exists
        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_server_certificate(ServerCertificateName=cert_name)
        snapshot.match("get-deleted-certificate-error", exc.value.response)

    @markers.aws.only_localstack
    def test_server_certificate_with_chain(self, aws_client, snapshot, upload_server_certificate):
        """Test uploading server certificate with certificate chain.

        Note: This test is LocalStack-only because AWS validates that the certificate
        chain properly signs the leaf certificate. Creating a valid chain requires
        generating matching CA certificates which is complex for testing purposes.
        """
        cert_name = f"cert-chain-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.key_value("ServerCertificateName"))

        # Upload server certificate with chain
        # Note: LocalStack accepts any chain; AWS validates the chain
        upload_response = aws_client.iam.upload_server_certificate(
            ServerCertificateName=cert_name,
            CertificateBody=SAMPLE_CERT_BODY,
            PrivateKey=SAMPLE_PRIVATE_KEY,
            CertificateChain=SAMPLE_CERT_CHAIN,
        )
        snapshot.match("upload-certificate-with-chain", upload_response)

        # Get certificate and verify chain is returned
        get_response = aws_client.iam.get_server_certificate(ServerCertificateName=cert_name)
        snapshot.match("get-certificate-with-chain", get_response)

        # Verify chain is present in response
        assert "CertificateChain" in get_response["ServerCertificate"]

        # Cleanup
        aws_client.iam.delete_server_certificate(ServerCertificateName=cert_name)

    @markers.aws.validated
    def test_server_certificate_errors(self, aws_client, snapshot, upload_server_certificate):
        """Test error cases for server certificate operations."""
        cert_name = f"cert-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.key_value("ServerCertificateName"))
        nonexistent_cert = "nonexistent-certificate"

        # Try to get non-existent certificate
        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_server_certificate(ServerCertificateName=nonexistent_cert)
        snapshot.match("get-nonexistent-certificate-error", exc.value.response)

        # Try to delete non-existent certificate
        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_server_certificate(ServerCertificateName=nonexistent_cert)
        snapshot.match("delete-nonexistent-certificate-error", exc.value.response)

        # Upload a certificate first
        upload_response = upload_server_certificate(cert_name=cert_name)
        snapshot.match("upload-certificate", upload_response)

        # Try to upload duplicate certificate (same name)
        with pytest.raises(ClientError) as exc:
            aws_client.iam.upload_server_certificate(
                ServerCertificateName=cert_name,
                CertificateBody=SAMPLE_CERT_BODY,
                PrivateKey=SAMPLE_PRIVATE_KEY,
            )
        snapshot.match("upload-duplicate-certificate-error", exc.value.response)
