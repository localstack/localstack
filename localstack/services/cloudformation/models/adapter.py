from localstack.services.cloudformation.service_models import GenericBaseModel


class ResourceProviderAdapter(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::EC2::VPC"

    def fetch_state(self, stack_name, resources):
        return None

    def get_cfn_attribute(self, attribute_name):
        return ""

    @classmethod
    def get_deploy_templates(cls):
        def _create(resource_id, resources, *args, **kwargs):
            # res = cls(resources[resource_id])
            # props = (resources[resource_id],)
            # TODO get resource provider & start deployment
            # TODO loop until final state reached
            ...

        def _delete(resource_id, resources, *args, **kwargs):
            # res = cls(resources[resource_id])
            # TODO
            ...

        # def _store_vpc_id(result, resource_id, resources, resource_type):
        #     resources[resource_id]["PhysicalResourceId"] = result["Vpc"]["VpcId"]

        return {
            "create": {
                {"function": _create},
            },
            "delete": [
                {"function": _delete},
            ],
        }
