import types

from moto.acm import models as acm_models

from localstack import config
from localstack.services.infra import start_moto_server


def apply_patches():
    def describe(self):
        result = describe_orig(self)
        cert = result.get("Certificate", {})
        sans = cert.get("SubjectAlternativeNames", [])

        # add missing attributes in ACM certs that cause Terraform to fail
        addenda = {
            "RenewalEligibility": "INELIGIBLE",
            "KeyUsages": [{"Name": "DIGITAL_SIGNATURE"}],
            "ExtendedKeyUsages": [],
            "Options": {"CertificateTransparencyLoggingPreference": "ENABLED"},
        }
        addenda["DomainValidationOptions"] = options = (
            getattr(self, "domain_validation_options", None) or []
        )
        if not options:
            options = addenda["DomainValidationOptions"] = [
                {"ValidationMethod": cert.get("ValidationMethod")}
            ]
        for san in sans:
            if san != cert.get("DomainName"):
                options.append(
                    {
                        "DomainName": san,
                        "ValidationMethod": cert.get("ValidationMethod"),
                    }
                )
        for option in options:
            option["DomainName"] = domain_name = option.get("DomainName") or cert.get("DomainName")
            option["ValidationDomain"] = option.get("ValidationDomain") or option["DomainName"]
            option["ValidationMethod"] = option.get("ValidationMethod") or "DNS"
            status = option.get("ValidationStatus")
            option["ValidationStatus"] = (
                "SUCCESS" if status in [None, "PENDING_VALIDATION"] else status
            )
            option["ValidationEmails"] = option.get("ValidationEmails") or [
                "admin@%s" % self.common_name
            ]
            test_record = {
                "Name": "test.%s" % domain_name,
                "Type": "CNAME",
                "Value": "test123",
            }
            option["ResourceRecord"] = option.get("ResourceRecord") or test_record

        for key, value in addenda.items():
            if not cert.get(key):
                cert[key] = value
        cert["Serial"] = str(cert.get("Serial") or "")
        return result

    describe_orig = acm_models.CertBundle.describe
    acm_models.CertBundle.describe = describe

    def wrap_request_certificate(backend):
        def request_certificate(self, domain_name, domain_validation_options, *args, **kwargs):
            cert_arn = request_certificate_orig(
                domain_name, domain_validation_options, *args, **kwargs
            )
            cert = self._certificates[cert_arn]
            if not hasattr(cert, "domain_validation_options"):
                cert.domain_validation_options = domain_validation_options
            return cert_arn

        request_certificate_orig = backend.request_certificate
        backend.request_certificate = types.MethodType(request_certificate, backend)

    for _, backend in acm_models.acm_backends.items():
        wrap_request_certificate(backend)


def start_acm(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_ACM
    apply_patches()
    return start_moto_server(
        "acm",
        port,
        name="ACM",
        update_listener=update_listener,
        asynchronous=asynchronous,
    )
