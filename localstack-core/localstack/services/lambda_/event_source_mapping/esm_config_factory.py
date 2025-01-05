import datetime

from localstack.aws.api.lambda_ import (
    CreateEventSourceMappingRequest,
    DestinationConfig,
    EventSourceMappingConfiguration,
    EventSourcePosition,
    RequestContext,
)
from localstack.services.lambda_ import hooks as lambda_hooks
from localstack.services.lambda_.event_source_mapping.esm_worker import EsmState, EsmStateReason
from localstack.services.lambda_.event_source_mapping.pipe_utils import (
    get_standardized_service_name,
)
from localstack.utils.aws.arns import lambda_event_source_mapping_arn, parse_arn
from localstack.utils.collections import merge_recursive
from localstack.utils.strings import long_uid


class EsmConfigFactory:
    request: CreateEventSourceMappingRequest
    context: RequestContext
    function_arn: str

    def __init__(
        self, request: CreateEventSourceMappingRequest, context: RequestContext, function_arn: str
    ):
        self.request = request
        self.function_arn = function_arn
        self.context = context

    def get_esm_config(self) -> EventSourceMappingConfiguration:
        """Creates an Event Source Mapping (ESM) configuration based on a create ESM request.
        * CreateEventSourceMapping API: https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html
        * CreatePipe API: https://docs.aws.amazon.com/eventbridge/latest/pipes-reference/API_CreatePipe.html
        The CreatePipe API covers largely the same parameters, but is better structured using hierarchical parameters.
        """
        service = ""
        if source_arn := self.request.get("EventSourceArn"):
            parsed_arn = parse_arn(source_arn)
            service = get_standardized_service_name(parsed_arn["service"])

        uuid = long_uid()

        default_source_parameters = {}
        default_source_parameters["UUID"] = uuid
        default_source_parameters["EventSourceMappingArn"] = lambda_event_source_mapping_arn(
            uuid, self.context.account_id, self.context.region
        )
        default_source_parameters["StateTransitionReason"] = EsmStateReason.USER_ACTION

        if service == "sqs":
            default_source_parameters["BatchSize"] = 10
            default_source_parameters["MaximumBatchingWindowInSeconds"] = 0
            default_source_parameters["StateTransitionReason"] = EsmStateReason.USER_INITIATED
        elif service == "kinesis":
            # TODO: test all defaults
            default_source_parameters["BatchSize"] = 100
            default_source_parameters["DestinationConfig"] = DestinationConfig(OnFailure={})
            default_source_parameters["BisectBatchOnFunctionError"] = False
            default_source_parameters["MaximumBatchingWindowInSeconds"] = 0
            default_source_parameters["MaximumRecordAgeInSeconds"] = -1
            default_source_parameters["MaximumRetryAttempts"] = -1
            default_source_parameters["ParallelizationFactor"] = 1
            default_source_parameters["StartingPosition"] = EventSourcePosition.TRIM_HORIZON
            default_source_parameters["TumblingWindowInSeconds"] = 0
            default_source_parameters["LastProcessingResult"] = EsmStateReason.NO_RECORDS_PROCESSED
        elif service == "dynamodbstreams":
            # TODO: test all defaults
            default_source_parameters["BatchSize"] = 100
            default_source_parameters["DestinationConfig"] = DestinationConfig(OnFailure={})
            default_source_parameters["BisectBatchOnFunctionError"] = False
            default_source_parameters["MaximumBatchingWindowInSeconds"] = 0
            default_source_parameters["MaximumRecordAgeInSeconds"] = -1
            default_source_parameters["MaximumRetryAttempts"] = -1
            default_source_parameters["ParallelizationFactor"] = 1
            default_source_parameters["StartingPosition"] = EventSourcePosition.TRIM_HORIZON
            default_source_parameters["TumblingWindowInSeconds"] = 0
            default_source_parameters["LastProcessingResult"] = EsmStateReason.NO_RECORDS_PROCESSED
        else:
            lambda_hooks.set_event_source_config_defaults.run(
                default_source_parameters, self.request, service
            )

            if not default_source_parameters:
                raise Exception(
                    f"Default Lambda Event Source Mapping parameters not implemented for service {service}. req={self.request} dict={default_source_parameters}"
                )

        # TODO: test whether merging actually happens recursively. Examples:
        # a) What happens if only one of the parameters for DocumentDBEventSourceConfig change?
        # b) Does a change of AmazonManagedKafkaEventSourceConfig.ConsumerGroupId affect flat parameters such as BatchSize and MaximumBatchingWindowInSeconds)?
        # c) Are FilterCriteria.Filters merged or replaced upon update?
        # TODO: can we ignore extra parameters from the request (e.g., Kinesis params for SQS source)?
        derived_source_parameters = merge_recursive(default_source_parameters, self.request)

        # TODO What happens when FunctionResponseTypes value or target service is invalid?
        if service in ["sqs", "kinesis", "dynamodbstreams"]:
            derived_source_parameters["FunctionResponseTypes"] = derived_source_parameters.get(
                "FunctionResponseTypes", []
            )

        state = EsmState.CREATING if self.request.get("Enabled", True) else EsmState.DISABLED
        esm_config = EventSourceMappingConfiguration(
            **derived_source_parameters,
            FunctionArn=self.function_arn,
            # TODO: last modified => does state transition affect this?
            LastModified=datetime.datetime.now(),
            State=state,
            # TODO: complete missing fields
        )
        # TODO: check whether we need to remove any more fields that are present in the request but should not be in the
        #  esm_config
        esm_config.pop("Enabled", "")
        esm_config.pop("FunctionName", "")
        if not esm_config.get("FilterCriteria", {}).get("Filters", []):
            esm_config.pop("FilterCriteria", "")
        return esm_config
