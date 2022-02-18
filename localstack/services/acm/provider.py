from moto.acm import acm_backends
from moto.acm import models as acm_models

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.acm import AcmApi, RequestCertificateRequest, RequestCertificateResponse
from localstack.services import moto
from localstack.utils.patch import patch


@patch(acm_models.CertBundle.describe)
def describe(describe_orig, self):
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
        option["ValidationStatus"] = "SUCCESS" if status in [None, "PENDING_VALIDATION"] else status
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


class AcmProvider(AcmApi):
    @handler("RequestCertificate", expand=False)
    def request_certificate(
        self,
        context: RequestContext,
        request: RequestCertificateRequest,
    ) -> RequestCertificateResponse:
        response: RequestCertificateResponse = moto.call_moto(context)

        cert_arn = response["CertificateArn"]
        backend = acm_backends.get(context.region)
        cert = backend._certificates[cert_arn]
        if not hasattr(cert, "domain_validation_options"):
            cert.domain_validation_options = request.get("DomainValidationOptions")

        return response
