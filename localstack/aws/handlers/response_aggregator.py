import logging
import os
import threading
from functools import lru_cache
from typing import Callable, Dict, List, Optional, Tuple, Union

from localstack_ext.bootstrap.licensing import ENV_LOCALSTACK_API_KEY

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.http import Response
from localstack.utils.analytics.response_aggregator import ResponseAggregator
from localstack.utils.aws.aws_responses import parse_response
from localstack.utils.aws.aws_stack import parse_arn

LOG = logging.getLogger(__name__)

ParameterPath = Union[str, Callable[[RequestContext, Response], str]]
ServiceName = str
OperationName = str
OperationNameList = List[OperationName]
OperationResourceNameMappings = List[Tuple[OperationNameList, ParameterPath]]


def get_operation_resource_name_mappings() -> Dict[ServiceName, OperationResourceNameMappings]:
    return {
        "kinesis": [
            (["CreateStream", "DeleteStream"], "StreamName"),
        ],
        "lambda": [
            (["CreateFunction", "DeleteFunction", "Invoke"], "FunctionName"),
        ],
        "s3": [
            (["CreateBucket", "DeleteBucket"], "Bucket"),
        ],
        "stepfunctions": [
            (["CreateStateMachine", "DeleteStateMachine"], "name"),
        ],
        "dynamodb": [
            (["CreateTable", "DeleteTable"], "TableName"),
        ],
        "cloudformation": [
            (["CreateStack", "DeleteStack"], "StackName"),
        ],
        "es": [
            (["CreateElasticsearchDomain", "DeleteElasticsearchDomain"], "DomainName"),
        ],
        "opensearch": [
            (["CreateDomain", "DeleteDomain"], "DomainName"),
        ],
        "firehose": [
            (["CreateDeliveryStream", "DeleteDeliveryStream"], "DeliveryStreamName"),
        ],
        "sns": [
            (["CreateTopic"], "Name"),
            (["DeleteTopic"], _get_resource_from_arn("TopicArn")),
        ],
        "sqs": [
            (["CreateQueue"], "QueueName"),
            (["DeleteQueue"], _get_queue_name_from_url),
        ],
    }


def get_resource_id(context: RequestContext, response: Response) -> Optional[str]:
    """
    Attempts to extract the ID (name) of a particular resource contained within the request or response object.
    For example, if the service is s3 and the operation is CreateBucket -> return the name of the bucket.
    The logic for extracting the resource name depends on the service and operation in question, so it has to be
    implemented manually on a per service/operation basis.
    """
    service_name = context.service.service_name
    operation_name = context.operation.name
    service_request = context.service_request

    if service_request is None:
        raise ValueError("No service request set")

    index = _get_operation_resource_name_index()

    if service_name not in index:
        return

    if operation_name not in index[service_name]:
        return

    path = index[service_name][operation_name]

    if callable(path):
        return path(context, response)

    return service_request.get(path)


class ResponseAggregatorHandler:
    def __init__(self):
        self.aggregator = ResponseAggregator()
        self.aggregator_thread = None
        self._aggregator_mutex = threading.Lock()
        # TODO FIXME: find a good way to actually check if pro is enabled
        self._is_pro_enabled = os.getenv(ENV_LOCALSTACK_API_KEY) is not None

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if response is None or context.service is None or context.operation is None:
            return
        if config.DISABLE_EVENTS:
            return

        # this condition will only be true only for the first call, so it makes sense to not acquire the lock every time
        if self.aggregator_thread is None:
            with self._aggregator_mutex:
                if self.aggregator_thread is None:
                    self.aggregator_thread = self.aggregator.start_thread()

        err_type = self._get_err_type(context, response) if response.status_code >= 400 else None
        service_name = context.service.service_name
        operation_name = context.operation.name
        resource_id = get_resource_id(context, response) if self._is_pro_enabled else None
        self.aggregator.add_response(
            service_name,
            operation_name,
            response.status_code,
            err_type=err_type,
            resource_id=resource_id,
        )

    def _get_err_type(self, context: RequestContext, response: Response) -> Optional[str]:
        """
        attempts to parse and return the error type from the response body, e.g. ResourceInUseException
        """
        try:
            parsed_response = parse_response(context, response)
            return parsed_response["Error"]["Code"]
        except Exception:
            LOG.exception("error parsing response")
            return None


@lru_cache()
def _get_operation_resource_name_index() -> Dict[ServiceName, Dict[OperationName, ParameterPath]]:
    index = {}

    for service_name, mappings in get_operation_resource_name_mappings().items():
        index[service_name] = {}
        for ops, path in mappings:
            for op in ops:
                index[service_name][op] = path

    return index


def _get_resource_from_arn(arn_parameter: str):
    def _extract(context, _response) -> str:
        return parse_arn(context.service_request.get(arn_parameter))["resource"]

    return _extract


def _get_queue_name_from_url(context, _response) -> str:
    from localstack.services.sqs.provider import get_queue_name_from_url

    return get_queue_name_from_url(context.service_request.get("QueueUrl"))
