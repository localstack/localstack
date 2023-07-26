import pytest
from moto import settings as moto_settings
from moto.ec2 import utils as ec2_utils

from localstack.aws.accounts import get_aws_account_id
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws import aws_stack
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

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
    def test_import_certificate(self, aws_client):
        certs_before = aws_client.acm.list_certificates().get("CertificateSummaryList", [])

        with pytest.raises(Exception) as exec_info:
            aws_client.acm.import_certificate(Certificate=b"CERT123", PrivateKey=b"KEY123")
        assert "PEM" in str(exec_info)

        private_key = ec2_utils.random_key_pair()["material"]
        result = None
        try:
            result = aws_client.acm.import_certificate(
                Certificate=DIGICERT_ROOT_CERT, PrivateKey=private_key
            )
            assert "CertificateArn" in result

            expected_arn = "arn:aws:acm:{0}:{1}:certificate".format(
                aws_stack.get_region(),
                get_aws_account_id(),
            )
            acm_cert_arn = result["CertificateArn"].split("/")[0]
            assert expected_arn == acm_cert_arn

            certs_after = aws_client.acm.list_certificates().get("CertificateSummaryList", [])
            assert len(certs_before) + 1 == len(certs_after)
        finally:
            if result is not None:
                aws_client.acm.delete_certificate(CertificateArn=result["CertificateArn"])

    def test_domain_validation(self, acm_request_certificate, aws_client):
        certificate_arn = acm_request_certificate()["CertificateArn"]
        result = aws_client.acm.describe_certificate(CertificateArn=certificate_arn)
        options = result["Certificate"]["DomainValidationOptions"]
        assert len(options) == 1

    def test_boto_wait_for_certificate_validation(
        self, acm_request_certificate, aws_client, monkeypatch
    ):
        monkeypatch.setattr(moto_settings, "ACM_VALIDATION_WAIT", 1)
        certificate_arn = acm_request_certificate()["CertificateArn"]
        waiter = aws_client.acm.get_waiter("certificate_validated")
        waiter.wait(CertificateArn=certificate_arn, WaiterConfig={"Delay": 0.5, "MaxAttempts": 3})

    @markers.parity.aws_validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Certificate.SignatureAlgorithm"])
    def test_certificate_for_subdomain_wildcard(
        self, acm_request_certificate, aws_client, snapshot, monkeypatch
    ):
        snapshot.add_transformer(snapshot.transform.key_value("OID"))
        snapshot.add_transformer(snapshot.transform.key_value("Serial"))
        monkeypatch.setattr(moto_settings, "ACM_VALIDATION_WAIT", 2)

        # request certificate for subdomain
        domain_name = f"test-domain-{short_uid()}.localhost.localstack.cloud"
        subdomain_pattern = f"*.{domain_name}"
        create_response = acm_request_certificate(
            ValidationMethod="DNS", DomainName=subdomain_pattern
        )
        cert_arn = create_response["CertificateArn"]

        snapshot.add_transformer(snapshot.transform.regex(domain_name, "<domain-name>"))
        cert_id = cert_arn.split("certificate/")[-1]
        snapshot.add_transformer(snapshot.transform.regex(cert_id, "<cert-id>"))
        snapshot.match("request-cert", create_response)

        def _get_cert_with_records():
            response = aws_client.acm.describe_certificate(CertificateArn=cert_arn)
            assert response["Certificate"]["DomainValidationOptions"][0]["ResourceRecord"]
            return response

        # wait for cert with ResourceRecord CNAME entry
        response = retry(_get_cert_with_records, sleep=1, retries=30)
        dns_options = response["Certificate"]["DomainValidationOptions"][0]["ResourceRecord"]
        snapshot.add_transformer(
            snapshot.transform.regex(dns_options["Name"].split(".")[0], "<record-prefix>")
        )
        snapshot.add_transformer(snapshot.transform.regex(dns_options["Value"], "<record-value>"))
        snapshot.match("describe-cert", response)

        if is_aws_cloud():
            # Wait until DNS entry has been added (needs to be done manually!)
            # Note: When running parity tests against AWS, we need to add the CNAME record to our DNS
            #  server (currently with gandi.net), to enable validation of the certificate.
            prompt = (
                f"Please add the following CNAME entry to the LocalStack DNS server, then hit [ENTER] once "
                f"the certificate has been validated in AWS: {dns_options['Name']} = {dns_options['Value']}"
            )
            input(prompt)

        def _get_cert_issued():
            response = aws_client.acm.describe_certificate(CertificateArn=cert_arn)
            assert response["Certificate"]["Status"] == "ISSUED"
            return response

        # get cert again after validation
        response = retry(_get_cert_issued, sleep=1, retries=30)
        snapshot.match("describe-cert-2", response)

        # also snapshot response of cert summaries via list_certificates
        response = aws_client.acm.list_certificates()
        summaries = response.get("CertificateSummaryList") or []
        matching = [cert for cert in summaries if cert["CertificateArn"] == cert_arn]
        snapshot.match("list-cert", matching)
