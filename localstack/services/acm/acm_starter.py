from moto.acm import models as acm_models
from localstack import config
from localstack.services.infra import start_moto_server


def apply_patches():
    def describe(self):
        # add missing attributes in ACM certs that cause Terraform to fail
        addenda = {
            'RenewalEligibility': 'INELIGIBLE',
            'KeyUsages': [{
                'Name': 'DIGITAL_SIGNATURE'
            }],
            'ExtendedKeyUsages': [],
            'DomainValidationOptions': [{
                'ValidationEmails': [
                    'admin@%s' % self.common_name
                ],
                'ValidationDomain': self.common_name,
                'DomainName': self.common_name
            }],
            'Options': {
                'CertificateTransparencyLoggingPreference': 'ENABLED'
            }
        }

        result = describe_orig(self)
        cert = result.get('Certificate', {})
        for key, value in addenda.items():
            if not cert.get(key):
                cert[key] = value
        cert['Serial'] = str(cert.get('Serial') or '')
        return result

    describe_orig = acm_models.CertBundle.describe
    acm_models.CertBundle.describe = describe


def start_acm(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_ACM
    apply_patches()
    return start_moto_server('acm', port, name='ACM', update_listener=update_listener, asynchronous=asynchronous)
