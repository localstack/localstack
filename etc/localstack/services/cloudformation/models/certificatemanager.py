from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack
from localstack.utils.common import select_attributes


class CertificateManagerCertificate(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::CertificateManager::Certificate"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("acm")
        result = client.list_certificates().get("CertificateSummaryList", [])
        domain_name = self.resolve_refs_recursively(
            stack_name, self.props.get("DomainName"), resources
        )
        result = [c for c in result if c["DomainName"] == domain_name]
        return (result or [None])[0]

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("CertificateArn")

    @classmethod
    def get_deploy_templates(cls):
        def _create_params(params, *args, **kwargs):
            result = select_attributes(
                params,
                [
                    "CertificateAuthorityArn",
                    "DomainName",
                    "DomainValidationOptions",
                    "SubjectAlternativeNames",
                    "Tags",
                    "ValidationMethod",
                ],
            )

            # adjust domain validation options
            valid_opts = result.get("DomainValidationOptions")
            if valid_opts:

                def _convert(opt):
                    res = select_attributes(opt, ["DomainName", "ValidationDomain"])
                    res.setdefault("ValidationDomain", res["DomainName"])
                    return res

                result["DomainValidationOptions"] = [_convert(opt) for opt in valid_opts]

            # adjust logging preferences
            logging_pref = result.get("CertificateTransparencyLoggingPreference")
            if logging_pref:
                result["Options"] = {"CertificateTransparencyLoggingPreference": logging_pref}

            return result

        return {
            "create": {"function": "request_certificate", "parameters": _create_params},
            "delete": {
                "function": "delete_certificate",
                "parameters": ["CertificateArn"],
            },
        }
