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

    def get_physical_resource_id(self, attribute=None, **kwargs):
        # return a synthetic ID here, as some parts of the CFn engine depend on PhysicalResourceId being resolvable
        return md5(canonical_json(self.props))

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

        return {
            "create": {"function": _no_op},
            "delete": {"function": _no_op},
        }
