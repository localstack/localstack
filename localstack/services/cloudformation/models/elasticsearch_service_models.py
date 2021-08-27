from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack


class ElasticsearchDomain(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Elasticsearch::Domain"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        domain_name = self._domain_name()
        if attribute == "Arn":
            return aws_stack.elasticsearch_domain_arn(domain_name)
        return domain_name

    def fetch_state(self, stack_name, resources):
        domain_name = self._domain_name()
        domain_name = self.resolve_refs_recursively(stack_name, domain_name, resources)
        return aws_stack.connect_to_service("es").describe_elasticsearch_domain(
            DomainName=domain_name
        )

    def _domain_name(self):
        return self.props.get("DomainName") or self.resource_id
