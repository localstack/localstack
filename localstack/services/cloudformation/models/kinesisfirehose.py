from localstack.services.cloudformation.deployment_utils import select_parameters
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import arns, aws_stack


class FirehoseDeliveryStream(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::KinesisFirehose::DeliveryStream"

    def fetch_state(self, stack_name, resources):
        stream_name = self.props.get("DeliveryStreamName") or self.logical_resource_id
        stream_name = self.resolve_refs_recursively(stack_name, stream_name, resources)
        return aws_stack.connect_to_service("firehose").describe_delivery_stream(
            DeliveryStreamName=stream_name
        )

    def get_cfn_attribute(self, attribute_name):
        if attribute_name == "Arn":
            return arns.firehose_stream_arn(self.props.get("DeliveryStreamName"))
        return super().get_cfn_attribute(attribute_name)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        if attribute == "Arn":
            return self.get_cfn_attribute("Arn")
        return self.props.get("DeliveryStreamName")

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_delivery_stream",
                "parameters": select_parameters(
                    "DeliveryStreamName",
                    "DeliveryStreamType",
                    "S3DestinationConfiguration",
                    "ElasticsearchDestinationConfiguration",
                    "AmazonopensearchserviceDestinationConfiguration",
                    "DeliveryStreamEncryptionConfigurationInput",
                    "ExtendedS3DestinationConfiguration",
                    "HttpEndpointDestinationConfiguration",
                    "KinesisStreamSourceConfiguration",
                    "RedshiftDestinationConfiguration",
                    "SplunkDestinationConfiguration",
                    "Tags",
                ),
            },
            "delete": {
                "function": "delete_delivery_stream",
                "parameters": {"DeliveryStreamName": "DeliveryStreamName"},
            },
        }
