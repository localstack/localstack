from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.json import canonical_json
from localstack.utils.strings import md5, short_uid


class CDKMetadata(GenericBaseModel):
    """Used by CDK for analytics/tracking purposes"""

    @staticmethod
    def cloudformation_type():
        return "AWS::CDK::Metadata"

    def fetch_state(self, stack_name, resources):
        return self.props

    @staticmethod
    def add_defaults(resource, stack_name: str):
        resource["Properties"]["PhysicalResourceId"] = (
            resource["Properties"].get("PhysicalResourceId") or f"cdk-meta-{short_uid()}"
        )

    def update_resource(self, new_resource, stack_name, resources):
        return True

    @staticmethod
    def get_deploy_templates():
        def _no_op(*args, **kwargs):
            pass

        def _handle_result(result, resource_id, resources, resource_type):
            resources[resource_id]["PhysicalResourceId"] = md5(
                canonical_json(resources[resource_id]["Properties"])
            )

        return {
            "create": {"function": _no_op, "result_handler": _handle_result},
            "delete": {"function": _no_op},
        }
