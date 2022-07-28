from localstack.services.cloudformation.service_models import GenericBaseModel


class CDKMetadata(GenericBaseModel):
    """Used by CDK for analytics/tracking purposes"""

    @staticmethod
    def cloudformation_type():
        return "AWS::CDK::Metadata"

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {},
        }
