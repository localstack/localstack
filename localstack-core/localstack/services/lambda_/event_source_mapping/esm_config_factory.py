import datetime

from localstack.aws.api.lambda_ import (
    CreateEventSourceMappingRequest,
    EventSourceMappingConfiguration,
)
from localstack.services.lambda_.event_source_mapping.esm_worker import EsmState, EsmStateReason
from localstack.utils.aws.arns import parse_arn
from localstack.utils.collections import merge_recursive
from localstack.utils.strings import long_uid


class EsmConfigFactory:
    request: CreateEventSourceMappingRequest
    function_arn: str

    def __init__(self, request: CreateEventSourceMappingRequest, function_arn: str):
        self.request = request
        self.function_arn = function_arn

    def get_esm_config(self) -> EventSourceMappingConfiguration:
        """Creates an Event Source Mapping (ESM) configuration based on a create ESM request.
        * CreateEventSourceMapping API: https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html
        * CreatePipe API: https://docs.aws.amazon.com/eventbridge/latest/pipes-reference/API_CreatePipe.html
        The CreatePipe API covers largely the same parameters, but is better structured using hierarchical parameters.
        """
        # TODO: handle special case where the "EventSourceArn" is optional (e.g., Apache Kafka: https://aws.amazon.com/blogs/compute/using-self-hosted-apache-kafka-as-an-event-source-for-aws-lambda/)
        source_arn = self.request["EventSourceArn"]
        parsed_arn = parse_arn(source_arn)
        service = parsed_arn["service"]

        default_source_parameters = {}
        if service == "sqs":
            default_source_parameters["BatchSize"] = 10
            default_source_parameters["MaximumBatchingWindowInSeconds"] = 0
        else:
            raise Exception(
                f"Default Lambda Event Source Mapping parameters not implemented for service {service}."
            )

        # TODO: test whether merging actually happens recursively. Examples:
        # a) What happens if only one of the parameters for DocumentDBEventSourceConfig change?
        # b) Does a change of AmazonManagedKafkaEventSourceConfig.ConsumerGroupId affect flat parameters such as BatchSize and MaximumBatchingWindowInSeconds)?
        # c) Are FilterCriteria.Filters merged or replaced upon update?
        derived_source_parameters = merge_recursive(default_source_parameters, self.request)
        derived_source_parameters["FunctionResponseTypes"] = derived_source_parameters.get(
            "FunctionResponseTypes", []
        )

        # TODO: check that only selected parameters from the request are used here and set defaults accordingly
        esm_config = EventSourceMappingConfiguration(
            **derived_source_parameters,
            UUID=long_uid(),
            FunctionArn=self.function_arn,
            # TODO: last modified => does state transition affect this?
            LastModified=datetime.datetime.now(),
            State=EsmState.CREATING,
            StateTransitionReason=EsmStateReason.USER_INITIATED,
            # TODO: complete missing fields (hardcoding for SQS test case now)
        )
        return esm_config
