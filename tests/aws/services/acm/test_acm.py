from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
import datetime
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
import pytest
from moto import settings as moto_settings

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from localstack_snapshot.snapshots.transformer import SortingTransformer
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


# TODO: functions taken from the cryptography docs, and
def generate_private_key() -> RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def generate_certificate_bytes(key: RSAPrivateKey) -> bytes:
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=10)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
            # Sign our certificate with our private key
        )
        .sign(key, hashes.SHA256())
    )

    return cert.public_bytes(Encoding.PEM)


class TestACM:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Certificate.CreatedAt",
            "$..Certificate.DomainValidationOptions..ResourceRecord",
            "$..Certificate.DomainValidationOptions..ValidationDomain",
            "$..Certificate.DomainValidationOptions..ValidationMethod",
            "$..Certificate.DomainValidationOptions..ValidationStatus",
            "$..Certificate.ExtendedKeyUsages",
            "$..Certificate.ExtendedKeyUsages..Name",
            "$..Certificate.ExtendedKeyUsages..OID",
            "$..Certificate.Issuer",
            "$..Certificate.KeyUsages",
            "$..Certificate.KeyUsages..Name",
            "$..Certificate.Options.CertificateTransparencyLoggingPreference",
            "$..Certificate.Serial",
            "$..Certificate.Subject",
        ]
    )
    def test_import_certificate(self, aws_client, cleanups, snapshot):
        with pytest.raises(Exception) as exc_info:
            aws_client.acm.import_certificate(Certificate=b"CERT123", PrivateKey=b"KEY123")
        assert exc_info.value.response["Error"]["Code"] == "ValidationException"

        private_key = generate_private_key()
        private_key_bytes = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
        )
        certificate_bytes = generate_certificate_bytes(private_key)
        result = aws_client.acm.import_certificate(
            Certificate=certificate_bytes, PrivateKey=private_key_bytes
        )
        certificate_arn = result["CertificateArn"]
        cert_id = certificate_arn.split("certificate/")[-1]
        snapshot.add_transformer(snapshot.transform.regex(cert_id, "<cert-id>"))

        cleanups.append(lambda: aws_client.acm.delete_certificate(CertificateArn=certificate_arn))
        snapshot.match("import-certificate-response", result)

        def _certificate_present():
            return aws_client.acm.describe_certificate(CertificateArn=certificate_arn)

        describe_res = retry(_certificate_present)

        snapshot.add_transformer(
            SortingTransformer("DomainValidationOptions", lambda o: o["DomainName"])
        )
        snapshot.add_transformer(SortingTransformer("SubjectAlternativeNames"))

        snapshot.match("describe-certificate-response", describe_res)

    @markers.aws.unknown
    def test_domain_validation(self, acm_request_certificate, aws_client):
        certificate_arn = acm_request_certificate()["CertificateArn"]
        result = aws_client.acm.describe_certificate(CertificateArn=certificate_arn)
        options = result["Certificate"]["DomainValidationOptions"]
        assert len(options) == 1

    @markers.aws.unknown
    def test_boto_wait_for_certificate_validation(
        self, acm_request_certificate, aws_client, monkeypatch
    ):
        monkeypatch.setattr(moto_settings, "ACM_VALIDATION_WAIT", 1)
        certificate_arn = acm_request_certificate()["CertificateArn"]
        waiter = aws_client.acm.get_waiter("certificate_validated")
        waiter.wait(CertificateArn=certificate_arn, WaiterConfig={"Delay": 0.5, "MaxAttempts": 3})

    @markers.aws.validated
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

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..ExtendedKeyUsages",
            "$..IssuedAt",
            "$..KeyUsages",
            "$..NotAfter",
            "$..NotBefore",
            "$..Status",
            "$..DomainValidationOptions..ValidationMethod",
            "$..DomainValidationOptions..ValidationEmails",
            "$..DomainValidationOptions..ValidationStatus",
            "$..FailureReason",
            "$..ResourceRecord",
            "$..SignatureAlgorithm",
            "$..Serial",
        ]
    )
    def test_create_certificate_for_multiple_alternative_domains(
        self, acm_request_certificate, aws_client, snapshot
    ):
        domain_name = "test.example.com"
        subject_alternative_names = [
            "test.example.com",
            "another.domain.com",
            "yet-another.domain.com",
            "*.test.example.com",
        ]

        create_response = acm_request_certificate(
            DomainName=domain_name, SubjectAlternativeNames=subject_alternative_names
        )

        cert_arn = create_response["CertificateArn"]

        def _certificate_ready():
            response = aws_client.acm.describe_certificate(CertificateArn=cert_arn)
            # expecting FAILED on aws due to not requesting a valid certificate
            # expecting ISSUED as default response from moto
            if response["Certificate"]["Status"] not in ["FAILED", "ISSUED"]:
                raise Exception("Certificate not yet ready")

        retry(_certificate_ready, sleep=1, retries=30)

        cert_list_response = aws_client.acm.list_certificates()
        cert_summaries = cert_list_response["CertificateSummaryList"]
        cert = next((cert for cert in cert_summaries if cert["CertificateArn"] == cert_arn), None)
        # Order of sns is not guaranteed therefor we sort them
        cert["SubjectAlternativeNameSummaries"].sort()
        cert_id = cert_arn.split("certificate/")[-1]
        snapshot.add_transformer(snapshot.transform.regex(cert_id, "<cert-id>"))
        snapshot.match("list-cert-summary-list", cert)

        cert_describe_response = aws_client.acm.describe_certificate(CertificateArn=cert_arn)
        cert_description = cert_describe_response["Certificate"]
        # Order of sns is not guaranteed therefor we sort them
        cert_description["SubjectAlternativeNames"].sort()
        cert_description["DomainValidationOptions"] = sorted(
            cert_description["DomainValidationOptions"], key=lambda x: x["DomainName"]
        )
        snapshot.match("describe-cert", cert_description)
