import logging
import time
from abc import ABC, abstractmethod

from localstack.aws.api.pipes import IncludeExecutionDataOption, LogLevel

LOG = logging.getLogger(__name__)


class PipeLogger(ABC):
    """Logger interface designed for EventBridge pipes logging:
    https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-logs.html
    """

    log_configuration: dict
    extra_fields: dict

    def __init__(self, log_configuration):
        self.log_configuration = log_configuration
        self.extra_fields = {}

    @abstractmethod
    def log_msg(self, message: dict) -> None:
        pass

    @property
    def include_execution_data(self) -> list[str] | None:
        return self.log_configuration.get("IncludeExecutionData")

    def set_fields(self, **kwargs):
        self.extra_fields.update(kwargs)

    def log(self, logLevel: str, **kwargs):
        if self.is_enabled_for(logLevel):
            message = {
                **self.extra_fields,
                "timestamp": int(time.time() * 1000),
                "logLevel": logLevel,
                **kwargs,
            }
            filtered_message = self.filter_message(message)
            LOG.debug(filtered_message)
            self.log_msg(filtered_message)

    def is_enabled_for(self, level: str):
        return log_levels().index(level) <= log_levels().index(self.get_effective_level())

    def get_effective_level(self):
        return self.log_configuration["Level"]

    def filter_message(self, message: dict) -> dict:
        # https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-logs.html#eb-pipes-logs-execution-data
        execution_data_fields = [
            "payload",
            "awsRequest",
            "awsResponse",
        ]
        fields_to_remove = (
            []
            if self.include_execution_data == [IncludeExecutionDataOption.ALL]
            else execution_data_fields
        )
        filtered_message = {
            key: value for key, value in message.items() if key not in fields_to_remove
        }
        return filtered_message


def log_levels():
    return [LogLevel.OFF, LogLevel.ERROR, LogLevel.INFO, LogLevel.TRACE]
