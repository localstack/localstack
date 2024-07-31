from localstack.aws.api.lambda_ import (
    EventSourceMappingConfiguration,
)
from localstack.aws.api.pipes import (
    DynamoDBStreamStartPosition,
    KinesisStreamStartPosition,
    PipeSourceDynamoDBStreamParameters,
    PipeSourceKinesisStreamParameters,
    PipeSourceParameters,
    PipeSourceSqsQueueParameters,
    PipeTargetInvocationType,
    PipeTargetLambdaFunctionParameters,
    PipeTargetParameters,
)
from localstack.services.lambda_.event_source_mapping.esm_event_processor import (
    EsmEventProcessor,
)
from localstack.services.lambda_.event_source_mapping.esm_worker import EsmStateReason, EsmWorker
from localstack.services.lambda_.event_source_mapping.pipe_loggers.noops_pipe_logger import (
    NoOpsPipeLogger,
)
from localstack.services.lambda_.event_source_mapping.pipe_utils import (
    get_internal_client,
    get_standardized_service_name,
)
from localstack.services.lambda_.event_source_mapping.pollers.dynamodb_poller import DynamoDBPoller
from localstack.services.lambda_.event_source_mapping.pollers.kinesis_poller import KinesisPoller
from localstack.services.lambda_.event_source_mapping.pollers.sqs_poller import SqsPoller
from localstack.services.lambda_.event_source_mapping.senders.lambda_sender import LambdaSender
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
            payload_dict=True,
        )

        # Logger
        logger = NoOpsPipeLogger()

        # Event Source Mapping processor
        esm_processor = EsmEventProcessor(sender=sender, logger=logger)

        # Poller
        source_arn = self.event_source_mapping_config["EventSourceArn"]
        parsed_source_arn = parse_arn(source_arn)
        source_service = get_standardized_service_name(parsed_source_arn["service"])
        source_client = get_internal_client(
            arn=source_arn,
            role_arn=self.function_role_arn,
            service_principal=ServicePrincipal.lambda_,
            source_arn=self.event_source_mapping_config["FunctionArn"],
        )
        filter_criteria = self.event_source_mapping_config.get("FilterCriteria", {"Filters": []})
        user_state_reason = EsmStateReason.USER_ACTION
        if source_service == "sqs":
            user_state_reason = EsmStateReason.USER_INITIATED
            source_parameters = PipeSourceParameters(
                FilterCriteria=filter_criteria,
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
                processor=esm_processor,
            )
        elif source_service == "kinesis":
            # TODO: map all supported ESM to Pipe parameters
            source_parameters = PipeSourceParameters(
                FilterCriteria=filter_criteria,
                KinesisStreamParameters=PipeSourceKinesisStreamParameters(
                    StartingPosition=KinesisStreamStartPosition[
                        self.event_source_mapping_config["StartingPosition"]
                    ],
                    BatchSize=self.event_source_mapping_config["BatchSize"],
                ),
            )
            poller = KinesisPoller(
                source_arn=source_arn,
                source_parameters=source_parameters,
                source_client=source_client,
                processor=esm_processor,
                invoke_identity_arn=self.function_role_arn,
                kinesis_namespace=True,
            )
        elif source_service == "dynamodbstreams":
            # TODO: map all supported ESM to Pipe parameters
            source_parameters = PipeSourceParameters(
                FilterCriteria=filter_criteria,
                DynamoDBStreamParameters=PipeSourceDynamoDBStreamParameters(
                    StartingPosition=DynamoDBStreamStartPosition[
                        self.event_source_mapping_config["StartingPosition"]
                    ],
                    BatchSize=self.event_source_mapping_config["BatchSize"],
                ),
            )
            poller = DynamoDBPoller(
                source_arn=source_arn,
                source_parameters=source_parameters,
                source_client=source_client,
                processor=esm_processor,
                # TODO: validate
                partner_resource_arn=None,
            )
        else:
            raise Exception(
                f"Unsupported event source mapping source service {source_service}. Please upvote or create a feature request."
            )

        esm_worker = EsmWorker(
            self.event_source_mapping_config,
            poller=poller,
            enabled=self.enabled,
            user_state_reason=user_state_reason,
        )
        return esm_worker
