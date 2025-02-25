from typing import Callable

import botocore.config

from localstack.aws.api.lambda_ import (
    EventSourceMappingConfiguration,
    FunctionResponseType,
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
from localstack.services.lambda_ import hooks as lambda_hooks
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
from localstack.services.lambda_.event_source_mapping.pollers.poller import Poller
from localstack.services.lambda_.event_source_mapping.pollers.sqs_poller import (
    DEFAULT_MAX_WAIT_TIME_SECONDS,
    SqsPoller,
)
from localstack.services.lambda_.event_source_mapping.senders.lambda_sender import LambdaSender
from localstack.utils.aws.arns import parse_arn
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.lambda_debug_mode.lambda_debug_mode import (
    DEFAULT_LAMBDA_DEBUG_MODE_TIMEOUT_SECONDS,
    is_lambda_debug_mode,
)


class PollerHolder:
    """Holds a `Callable` function `create_poller_fn` used to create a Poller. Useful when creating Pollers downstream via hooks."""

    create_poller_fn: Callable[..., Poller] | None = None


class EsmWorkerFactory:
    esm_config: EventSourceMappingConfiguration
    function_role_arn: str
    enabled: bool

    def __init__(self, esm_config, function_role, enabled):
        self.esm_config = esm_config
        self.function_role_arn = function_role
        self.enabled = enabled

    def get_esm_worker(self) -> EsmWorker:
        # Sender (always Lambda)
        function_arn = self.esm_config["FunctionArn"]

        if is_lambda_debug_mode():
            timeout_seconds = DEFAULT_LAMBDA_DEBUG_MODE_TIMEOUT_SECONDS
        else:
            # 900s is the maximum amount of time a Lambda can run for.
            lambda_max_timeout_seconds = 900
            invoke_timeout_buffer_seconds = 5
            timeout_seconds = lambda_max_timeout_seconds + invoke_timeout_buffer_seconds

        lambda_client = get_internal_client(
            arn=function_arn,  # Only the function_arn is necessary since the Lambda should be able to invoke itself
            client_config=botocore.config.Config(
                retries={
                    "total_max_attempts": 1
                },  # Disable retries, to prevent re-invoking the Lambda
                read_timeout=timeout_seconds,
                tcp_keepalive=True,
            ),
        )
        sender = LambdaSender(
            target_arn=function_arn,
            target_parameters=PipeTargetParameters(
                LambdaFunctionParameters=PipeTargetLambdaFunctionParameters(
                    InvocationType=PipeTargetInvocationType.REQUEST_RESPONSE
                )
            ),
            target_client=lambda_client,
            payload_dict=True,  # TODO: This should be handled better since not all payloads in ESM are in the form { "Records" : List[Dict]}
            report_batch_item_failures=self.esm_config.get("FunctionResponseTypes")
            == [FunctionResponseType.ReportBatchItemFailures],
        )

        # Logger
        logger = NoOpsPipeLogger()

        # Event Source Mapping processor
        esm_processor = EsmEventProcessor(sender=sender, logger=logger)

        # Poller
        source_service = ""
        source_client = None
        source_arn = self.esm_config.get("EventSourceArn", "")
        if source_arn:
            parsed_source_arn = parse_arn(source_arn)
            source_service = get_standardized_service_name(parsed_source_arn["service"])
            source_client = get_internal_client(
                arn=source_arn,
                role_arn=self.function_role_arn,
                service_principal=ServicePrincipal.lambda_,
                source_arn=self.esm_config["FunctionArn"],
                client_config=botocore.config.Config(
                    retries={"total_max_attempts": 1},  # Disable retries
                    read_timeout=max(
                        self.esm_config.get(
                            "MaximumBatchingWindowInSeconds", DEFAULT_MAX_WAIT_TIME_SECONDS
                        ),
                        60,
                    )
                    + 5,  # Extend read timeout (with 5s buffer) for long-polling
                    # Setting tcp_keepalive to true allows the boto client to keep
                    # a long-running TCP connection when making calls to the gateway.
                    # This ensures long-poll calls do not prematurely have their socket
                    # connection marked as stale if no data is transferred for a given
                    # period of time hence preventing premature drops or resets of the
                    # connection.
                    # See https://aws.amazon.com/blogs/networking-and-content-delivery/implementing-long-running-tcp-connections-within-vpc-networking/
                    tcp_keepalive=True,
                ),
            )

        filter_criteria = self.esm_config.get("FilterCriteria", {"Filters": []})
        user_state_reason = EsmStateReason.USER_ACTION
        if source_service == "sqs":
            user_state_reason = EsmStateReason.USER_INITIATED
            source_parameters = PipeSourceParameters(
                FilterCriteria=filter_criteria,
                SqsQueueParameters=PipeSourceSqsQueueParameters(
                    BatchSize=self.esm_config["BatchSize"],
                    MaximumBatchingWindowInSeconds=self.esm_config[
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
            optional_params = {}
            dead_letter_config_arn = (
                self.esm_config.get("DestinationConfig", {}).get("OnFailure", {}).get("Destination")
            )
            if dead_letter_config_arn:
                optional_params["DeadLetterConfig"] = {"Arn": dead_letter_config_arn}
            source_parameters = PipeSourceParameters(
                FilterCriteria=filter_criteria,
                KinesisStreamParameters=PipeSourceKinesisStreamParameters(
                    StartingPosition=KinesisStreamStartPosition[
                        self.esm_config["StartingPosition"]
                    ],
                    BatchSize=self.esm_config["BatchSize"],
                    MaximumRetryAttempts=self.esm_config["MaximumRetryAttempts"],
                    **optional_params,
                ),
            )
            poller = KinesisPoller(
                esm_uuid=self.esm_config["UUID"],
                source_arn=source_arn,
                source_parameters=source_parameters,
                source_client=source_client,
                processor=esm_processor,
                invoke_identity_arn=self.function_role_arn,
                kinesis_namespace=True,
            )
        elif source_service == "dynamodbstreams":
            # TODO: map all supported ESM to Pipe parameters
            optional_params = {}
            dead_letter_config_arn = (
                self.esm_config.get("DestinationConfig", {}).get("OnFailure", {}).get("Destination")
            )
            if dead_letter_config_arn:
                optional_params["DeadLetterConfig"] = {"Arn": dead_letter_config_arn}
            source_parameters = PipeSourceParameters(
                FilterCriteria=filter_criteria,
                DynamoDBStreamParameters=PipeSourceDynamoDBStreamParameters(
                    StartingPosition=DynamoDBStreamStartPosition[
                        self.esm_config["StartingPosition"]
                    ],
                    BatchSize=self.esm_config["BatchSize"],
                    MaximumRetryAttempts=self.esm_config["MaximumRetryAttempts"],
                    **optional_params,
                ),
            )
            poller = DynamoDBPoller(
                esm_uuid=self.esm_config["UUID"],
                source_arn=source_arn,
                source_parameters=source_parameters,
                source_client=source_client,
                processor=esm_processor,
            )
        else:
            poller_holder = PollerHolder()
            lambda_hooks.create_event_source_poller.run(
                poller_holder, source_service, self.esm_config
            )

            if not poller_holder.create_poller_fn:
                raise Exception(
                    f"Unsupported event source mapping source service {source_service}. Please upvote or create a feature request."
                )

            poller: Poller = poller_holder.create_poller_fn(
                arn=source_arn,
                client=source_client,
                processor=esm_processor,
            )

        esm_worker = EsmWorker(
            self.esm_config,
            poller=poller,
            enabled=self.enabled,
            user_state_reason=user_state_reason,
        )
        return esm_worker
