from moto.acm import models as acm_models

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.acm import AcmApi, RequestCertificateRequest, RequestCertificateResponse
from localstack.services import moto
from localstack.utils.objects import singleton_factory
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
    addenda["DomainValidationOptions"] = options = cert.get("DomainValidationOptions")
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


@singleton_factory
def patch_cert_bundle_pickling():
    """Apply patches to pickle CertBundle base models. It prevents the "cannot pickle 'builtins.Certificate'" errors"""
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509 import load_pem_x509_certificate
    from moto.acm.models import CertBundle

    def cert_set_state(self, state, *args, **kwargs):
        certificate = state.get("cert")
        state["_cert"] = load_pem_x509_certificate(certificate, default_backend())
        self.__dict__.update(state)

    CertBundle.__setstate__ = cert_set_state

    def cert_get_state(self, *args, **kwargs):
        state = self.__dict__.copy()
        # pop builtins.Certificate
        state.pop("_cert", None)
        return state

    CertBundle.__getstate__ = cert_get_state


patch_cert_bundle_pickling()


class AcmProvider(AcmApi):
    @handler("RequestCertificate", expand=False)
    def request_certificate(
        self,
        context: RequestContext,
        request: RequestCertificateRequest,
    ) -> RequestCertificateResponse:
        response: RequestCertificateResponse = moto.call_moto(context)

        cert_arn = response["CertificateArn"]
        backend = acm_models.acm_backends[context.account_id][context.region]
        cert = backend._certificates[cert_arn]
        if not hasattr(cert, "domain_validation_options"):
            cert.domain_validation_options = request.get("DomainValidationOptions")

        return response
