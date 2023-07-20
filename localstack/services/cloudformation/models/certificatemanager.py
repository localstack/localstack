from localstack.aws.connect import connect_to
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.common import select_attributes


class CertificateManagerCertificate(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::CertificateManager::Certificate"

    def fetch_state(self, stack_name, resources):
        client = connect_to().acm
        result = client.list_certificates().get("CertificateSummaryList", [])
        domain_name = self.props.get("DomainName")
        result = [c for c in result if c["DomainName"] == domain_name]
        return (result or [None])[0]

    @classmethod
    def get_deploy_templates(cls):
        def _create_params(
            properties: dict, logical_resource_id: str, resource: dict, stack_name: str
        ) -> dict:
            result = select_attributes(
                properties,
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

        def _handle_result(result, resource_id, resources, resource_type):
            resource = resources[resource_id]
            resource["Properties"]["CertificateArn"] = resource["PhysicalResourceId"] = result[
                "CertificateArn"
            ]

        return {
            "create": {
                "function": "request_certificate",
                "parameters": _create_params,
                "result_handler": _handle_result,
            },
            "delete": {
                "function": "delete_certificate",
                "parameters": ["CertificateArn"],
            },
        }
