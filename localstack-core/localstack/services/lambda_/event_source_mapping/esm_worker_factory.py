from localstack_ext.aws.api.pipes import (
    PipeSourceParameters,
    PipeSourceSqsQueueParameters,
    PipeTargetInvocationType,
    PipeTargetLambdaFunctionParameters,
    PipeTargetParameters,
)
from localstack_ext.services.pipes.pipe_utils import get_internal_client
from localstack_ext.services.pipes.pollers.sqs_poller import SqsPoller
from localstack_ext.services.pipes.senders.lambda_sender import LambdaSender

from localstack.aws.api.lambda_ import (
    EventSourceMappingConfiguration,
)
from localstack.services.lambda_.event_source_mapping.esm_worker import EsmWorker
from localstack.utils.aws.arns import parse_arn
from localstack.utils.aws.client_types import ServicePrincipal


class EsmWorkerFactory:
    event_source_mapping_config: EventSourceMappingConfiguration
    function_role_arn: str
    enabled: bool

    def __init__(self, event_source_mapping_config, function_role, enabled):
        self.event_source_mapping_config = event_source_mapping_config
        self.function_role_arn = function_role
        self.enabled = enabled

    def get_esm_worker(self) -> EsmWorker:
        # Poller
        source_arn = self.event_source_mapping_config["EventSourceArn"]
        parsed_source_arn = parse_arn(source_arn)
        source_service = parsed_source_arn["service"]
        source_client = get_internal_client(
            arn=source_arn,
            role_arn=self.function_role_arn,
            service_principal=ServicePrincipal.lambda_,
            source_arn=self.event_source_mapping_config["FunctionArn"],
        )
        if source_service == "sqs":
            source_parameters = PipeSourceParameters(
                SqsQueueParameters=PipeSourceSqsQueueParameters(
                    BatchSize=self.event_source_mapping_config["BatchSize"],
                    MaximumBatchingWindowInSeconds=self.event_source_mapping_config[
                        "MaximumBatchingWindowInSeconds"
                    ],
                ),
            )
            poller = SqsPoller(
                source_arn=source_arn,
                source_parameters=source_parameters,
                source_client=source_client,
            )
        else:
            raise Exception(
                f"Unsupported event source mapping source service {source_service}. Please upvote or create a feature request."
            )

        # Sender (always Lambda)
        function_arn = self.event_source_mapping_config["FunctionArn"]
        lambda_client = get_internal_client(
            arn=function_arn,
            role_arn=self.function_role_arn,
            service_principal=ServicePrincipal.pipes,
            source_arn=self.event_source_mapping_config["FunctionArn"],
        )
        sender = LambdaSender(
            target_arn=function_arn,
            target_parameters=PipeTargetParameters(
                LambdaFunctionParameters=PipeTargetLambdaFunctionParameters(
                    InvocationType=PipeTargetInvocationType.REQUEST_RESPONSE
                )
            ),
            target_client=lambda_client,
        )
        esm_worker = EsmWorker(
            self.event_source_mapping_config, poller=poller, sender=sender, enabled=self.enabled
        )
        return esm_worker
