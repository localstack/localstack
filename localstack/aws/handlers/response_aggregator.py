import logging
import os
import threading
from typing import Optional

import xmltodict
from localstack_ext.bootstrap.licensing import ENV_LOCALSTACK_API_KEY

from localstack import config
from localstack.aws.api import RequestContext, ServiceRequest
from localstack.aws.chain import HandlerChain
from localstack.http import Response
from localstack.utils.analytics.response_aggregator import ResponseAggregator
from localstack.utils.aws.aws_responses import parse_response

LOG = logging.getLogger(__name__)


def get_resource_id(
    service_name: str, operation_name: str, service_request: ServiceRequest, response: Response
) -> Optional[str]:
    if service_name == "kinesis" and operation_name in {"CreateStream", "DeleteStream"}:
        return service_request.get("StreamName")
    if service_name == "lambda" and operation_name in {
        "CreateFunction",
        "DeleteFunction",
        "Invoke",
    }:
        return service_request.get("FunctionName")
    if service_name == "s3" and operation_name in {"CreateBucket", "DeleteBucket"}:
        return service_request.get("Bucket")
    if service_name == "stepfunctions" and operation_name in {
        "CreateStateMachine",
        "DeleteStateMachine",
    }:
        return service_request.get("name")
    if service_name == "dynamodb" and operation_name in {"CreateTable", "DeleteTable"}:
        return service_request.get("TableName")
    if service_name == "cloudformation" and operation_name == "CreateStack":
        return service_request.get("StackName")
    if service_name == "es" and operation_name in {
        "CreateElasticsearchDomain",
        "DeleteElasticsearchDomain",
    }:
        return service_request.get("DomainName")
    if service_name == "opensearch" and operation_name in {"CreateDomain", "DeleteDomain"}:
        return service_request.get("DomainName")
    if service_name == "firehose" and operation_name in {
        "CreateDeliveryStream",
        "DeleteDeliveryStream",
    }:
        return service_request.get("DeliveryStreamName")
    if service_name == "apigateway":
        if operation_name == "DeleteRestApi":
            return service_request.get("restApiId")
        if operation_name == "CreateRestApi":
            return response.get_json(force=True, silent=True).get("id")
    if service_name == "sqs":
        if operation_name == "CreateQueue":
            response_data = xmltodict.parse(response.get_data(as_text=True))
            return (
                response_data.get("CreateQueueResponse", {})
                .get("CreateQueueResult", {})
                .get("QueueUrl")
            )
        if operation_name == "DeleteQueue":
            return service_request.get("QueueUrl")
    if service_name == "sns":
        if operation_name == "CreateTopic":
            response_data = xmltodict.parse(response.get_data(as_text=True))
            return (
                response_data.get("CreateTopicResponse", {})
                .get("CreateTopicResult", {})
                .get("TopicArn")
            )
        if operation_name == "DeleteTopic":
            return service_request.get("TopicArn")

    return None


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
        resource_id = (
            get_resource_id(service_name, operation_name, context.service_request, response)
            if self._is_pro_enabled
            else None
        )
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
