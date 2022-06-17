import pytest
from moto.ec2 import utils as ec2_utils

from localstack.aws.accounts import get_aws_account_id
from localstack.utils.aws import aws_stack

DIGICERT_ROOT_CERT = """
-----BEGIN CERTIFICATE-----
MIICRjCCAc2gAwIBAgIQC6Fa+h3foLVJRK/NJKBs7DAKBggqhkjOPQQDAzBlMQsw
CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
ZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3Qg
RzMwHhcNMTMwODAxMTIwMDAwWhcNMzgwMTE1MTIwMDAwWjBlMQswCQYDVQQGEwJV
UzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQu
Y29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgRzMwdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAAQZ57ysRGXtzbg/WPuNsVepRC0FFfLvC/8QdJ+1YlJf
Zn4f5dwbRXkLzMZTCp2NXQLZqVneAlr2lSoOjThKiknGvMYDOAdfVdp+CW7if17Q
RSAPWXYQ1qAk8C3eNvJsKTmjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/
BAQDAgGGMB0GA1UdDgQWBBTL0L2p4ZgFUaFNN6KDec6NHSrkhDAKBggqhkjOPQQD
AwNnADBkAjAlpIFFAmsSS3V0T8gj43DydXLefInwz5FyYZ5eEJJZVrmDxxDnOOlY
JjZ91eQ0hjkCMHw2U/Aw5WJjOpnitqM7mzT6HtoQknFekROn3aRukswy1vUhZscv
6pZjamVFkpUBtA==
-----END CERTIFICATE-----
"""


class TestACM:
    def test_import_certificate(self, acm_client):
        certs_before = acm_client.list_certificates().get("CertificateSummaryList", [])

        with pytest.raises(Exception) as exec_info:
            acm_client.import_certificate(Certificate=b"CERT123", PrivateKey=b"KEY123")
        assert "PEM" in str(exec_info)

        private_key = ec2_utils.random_key_pair()["material"]
        result = None
        try:
            result = acm_client.import_certificate(
                Certificate=DIGICERT_ROOT_CERT, PrivateKey=private_key
            )
            assert "CertificateArn" in result

            expected_arn = "arn:aws:acm:{0}:{1}:certificate".format(
                aws_stack.get_region(),
                get_aws_account_id(),
            )
            acm_cert_arn = result["CertificateArn"].split("/")[0]
            assert expected_arn == acm_cert_arn

            certs_after = acm_client.list_certificates().get("CertificateSummaryList", [])
            assert len(certs_before) + 1 == len(certs_after)
        finally:
            if result is not None:
                acm_client.delete_certificate(CertificateArn=result["CertificateArn"])

    def test_domain_validation(self, acm_client, acm_request_certificate):
        certificate_arn = acm_request_certificate()
        result = acm_client.describe_certificate(CertificateArn=certificate_arn)
        options = result["Certificate"]["DomainValidationOptions"]
        assert len(options) == 1

    def test_boto_wait_for_certificate_validation(self, acm_client, acm_request_certificate):
        certificate_arn = acm_request_certificate()
        waiter = acm_client.get_waiter("certificate_validated")
        waiter.wait(CertificateArn=certificate_arn, WaiterConfig={"Delay": 0, "MaxAttempts": 1})
