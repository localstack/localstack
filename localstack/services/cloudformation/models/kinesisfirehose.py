from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import select_parameters
from localstack.services.cloudformation.service_models import GenericBaseModel


class FirehoseDeliveryStream(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::KinesisFirehose::DeliveryStream"

    def fetch_state(self, stack_name, resources):
        stream_name = self.props.get("DeliveryStreamName") or self.logical_resource_id
        return connect_to().firehose.describe_delivery_stream(DeliveryStreamName=stream_name)

    @staticmethod
    def get_deploy_templates():
        def _handle_result(result, resource_id, resources, resource_type):
            resources[resource_id]["Properties"]["Arn"] = result["DeliveryStreamARN"]
            resources[resource_id]["PhysicalResourceId"] = resources[resource_id]["Properties"][
                "DeliveryStreamName"
            ]

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
                "result_handler": _handle_result,
            },
            "delete": {
                "function": "delete_delivery_stream",
                "parameters": {"DeliveryStreamName": "DeliveryStreamName"},
            },
        }
