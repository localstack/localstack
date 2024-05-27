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
    CreateEventSourceMappingRequest,
    EventSourceMappingConfiguration,
)
from localstack.services.lambda_.event_source_mapping.esm_worker import EsmWorker
from localstack.utils.aws.arns import parse_arn
from localstack.utils.aws.client_types import ServicePrincipal


class EsmWorkerFactory:
    event_source_mapping_config: EventSourceMappingConfiguration
    # TODO: fix other attributes definitions (it's getting messy)

    def __init__(
        self,
        event_source_mapping_config: EventSourceMappingConfiguration,
        function_role: str,
        derived_source_parameters_esm: dict,
        enabled: bool,
    ):
        self.event_source_mapping_config = event_source_mapping_config
        self.function_role_arn = function_role
        self.derived_source_parameters_esm = derived_source_parameters_esm
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
            poller = SqsPoller(
                source_arn=source_arn,
                # TODO: fix this hack
                source_parameters=convert_pipes_to_esm_source_parameters(
                    self.derived_source_parameters_esm
                ),
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


def convert_esm_to_pipes_source_parameters(
    request: CreateEventSourceMappingRequest,
) -> PipeSourceParameters:
    # TODO: needs the service, consider delegating this to service-specific classes (different for Pipes + ESM)
    """Maps optional source parameters from the unstructured Lambda ESM request to structured pipe source parameters."""
    # https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html
    # TODO: only hardcoded for SQS!
    return PipeSourceParameters(
        SqsQueueParameters=PipeSourceSqsQueueParameters(
            BatchSize=request.get("BatchSize"),
            MaximumBatchingWindowInSeconds=request.get("MaximumBatchingWindowInSeconds", 0),
        ),
    )


def convert_pipes_to_esm_source_parameters(
    source_parameters: PipeSourceParameters,
) -> EventSourceMappingConfiguration:
    # TODO: only hardcoded for SQS!
    return EventSourceMappingConfiguration(
        BatchSize=source_parameters["SqsQueueParameters"]["BatchSize"],
        MaximumBatchingWindowInSeconds=source_parameters["SqsQueueParameters"].get(
            "MaximumBatchingWindowInSeconds", 0
        ),
    )
