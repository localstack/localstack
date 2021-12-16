import unittest

from moto.ec2 import utils as ec2_utils

from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid

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


class TestACM(unittest.TestCase):
    def test_import_certificate(self):
        acm = aws_stack.create_external_boto_client("acm")

        certs_before = acm.list_certificates().get("CertificateSummaryList", [])

        with self.assertRaises(Exception) as ctx:
            acm.import_certificate(Certificate=b"CERT123", PrivateKey=b"KEY123")
        self.assertIn("PEM", str(ctx.exception))

        private_key = ec2_utils.random_key_pair()["material"]
        result = acm.import_certificate(Certificate=DIGICERT_ROOT_CERT, PrivateKey=private_key)
        self.assertIn("CertificateArn", result)

        expected_arn = "arn:aws:acm:{0}:{1}:certificate".format(
            aws_stack.get_region(), TEST_AWS_ACCOUNT_ID
        )
        acm_cert_arn = result["CertificateArn"].split("/")[0]
        self.assertEqual(expected_arn, acm_cert_arn)

        certs_after = acm.list_certificates().get("CertificateSummaryList", [])
        self.assertEqual(len(certs_before) + 1, len(certs_after))

    def test_domain_validation(self):
        acm = aws_stack.create_external_boto_client("acm")

        domain_name = "example-%s.com" % short_uid()
        options = [{"DomainName": domain_name, "ValidationDomain": domain_name}]
        result = acm.request_certificate(DomainName=domain_name, DomainValidationOptions=options)
        self.assertIn("CertificateArn", result)

        result = acm.describe_certificate(CertificateArn=result["CertificateArn"])
        options = result["Certificate"]["DomainValidationOptions"]
        self.assertEqual(1, len(options))
