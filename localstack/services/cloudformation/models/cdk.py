from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.json import canonical_json
from localstack.utils.strings import md5


class CDKMetadata(GenericBaseModel):
    """Used by CDK for analytics/tracking purposes"""

    @staticmethod
    def cloudformation_type():
        return "AWS::CDK::Metadata"

    def fetch_state(self, stack_name, resources):
        return self.props

    def update_resource(self, new_resource, stack_name, resources):
        return True

    @staticmethod
    def get_deploy_templates():
        def _no_op(*args, **kwargs):
            pass

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = md5(canonical_json(resource["Properties"]))

        return {
            "create": {"function": _no_op, "result_handler": _handle_result},
            "delete": {"function": _no_op},
        }
