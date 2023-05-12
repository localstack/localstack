from typing import Final, Optional

from botocore.exceptions import ClientError

from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_callback import (
    StateTaskServiceCallback,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.utils.aws import aws_stack
from localstack.utils.strings import camel_to_snake_case


class StateTaskServiceDynamoDB(StateTaskServiceCallback):
    _ERROR_NAME_AWS: Final[str] = "DynamoDB.AmazonDynamoDBException"

    _SUPPORTED_API_PARAM_BINDINGS: Final[dict[str, set[str]]] = {
        "getitem": {
            "Key",
            "TableName",
            "AttributesToGet",
            "ConsistentRead",
            "ExpressionAttributeNames",
            "ProjectionExpression",
            "ReturnConsumedCapacity",
        },
        "putitem": {
            "Item",
            "TableName",
            "ConditionalOperator",
            "ConditionExpression",
            "Expected",
            "ExpressionAttributeNames",
            "ExpressionAttributeValues",
            "ReturnConsumedCapacity",
            "ReturnItemCollectionMetrics",
            "ReturnValues",
        },
        "deleteitem": {
            "Key",
            "TableName",
            "ConditionalOperator",
            "ConditionExpression",
            "Expected",
            "ExpressionAttributeNames",
            "ExpressionAttributeValues",
            "ReturnConsumedCapacity",
            "ReturnItemCollectionMetrics",
            "ReturnValues",
        },
        "updateitem": {
            "Key",
            "TableName",
            "AttributeUpdates",
            "ConditionalOperator",
            "ConditionExpression",
            "Expected",
            "ExpressionAttributeNames",
            "ExpressionAttributeValues",
            "ReturnConsumedCapacity",
            "ReturnItemCollectionMetrics",
            "ReturnValues",
            "UpdateExpression",
        },
    }

    def _get_supported_parameters(self) -> Optional[set[str]]:
        return self._SUPPORTED_API_PARAM_BINDINGS.get(self.resource.api_action.lower(), None)

    @staticmethod
    def _error_cause_from_client_error(client_error: ClientError) -> tuple[str, str]:
        error_code: str = client_error.response["Error"]["Code"]
        error_msg: str = client_error.response["Error"]["Message"]
        response_details = "; ".join(
            [
                "Service: DynamoDB",
                f"Status Code: {client_error.response['ResponseMetadata']['HTTPStatusCode']}",
                f"Error Code: {error_code}",
                f"Request ID: {client_error.response['ResponseMetadata']['RequestId']}",
                "Proxy: null",
            ]
        )
        error = f"DynamoDB.{error_code}"
        cause = f"{error_msg} ({response_details})"
        return error, cause

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        if isinstance(ex, ClientError):
            error, cause = self._error_cause_from_client_error(ex)
            error_name = CustomErrorName(error)
            return FailureEvent(
                error_name=error_name,
                event_type=HistoryEventType.TaskFailed,
                event_details=EventDetails(
                    taskFailedEventDetails=TaskFailedEventDetails(
                        error=error,
                        cause=cause,
                        resource=self._get_sfn_resource(),
                        resourceType=self._get_sfn_resource_type(),
                    )
                ),
            )
        else:
            return FailureEvent(
                error_name=CustomErrorName(self._ERROR_NAME_AWS),
                event_type=HistoryEventType.TaskFailed,
                event_details=EventDetails(
                    taskFailedEventDetails=TaskFailedEventDetails(
                        error=self._ERROR_NAME_AWS,
                        cause=str(ex),  # TODO: update to report expected cause.
                        resource=self._get_sfn_resource(),
                        resourceType=self._get_sfn_resource_type(),
                    )
                ),
            )

    def _eval_service_task(self, env: Environment, parameters: dict) -> None:
        api_action = camel_to_snake_case(self.resource.api_action)

        dynamodb_client = aws_stack.create_external_boto_client("dynamodb")
        response = getattr(dynamodb_client, api_action)(**parameters)
        response.pop("ResponseMetadata", None)
        env.stack.append(response)
