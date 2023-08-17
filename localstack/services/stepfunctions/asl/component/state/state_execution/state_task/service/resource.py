from __future__ import annotations

import abc
from itertools import takewhile
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.component import Component
from localstack.utils.aws import aws_stack


class ResourceCondition(str):
    WaitForTaskToken = "waitForTaskToken"
    Sync2 = "sync:2"
    Sync = "sync"


class ResourceARN:
    arn: str
    partition: str
    service: str
    region: str
    account: str
    task_type: str
    name: str
    option: str

    def __init__(
        self,
        arn: str,
        partition: str,
        service: str,
        region: str,
        account: str,
        task_type: str,
        name: str,
        option: Optional[str],
    ):
        self.arn = arn
        self.partition = partition
        self.service = service
        self.region = region
        self.account = account
        self.task_type = task_type
        self.name = name
        self.option = option

    @staticmethod
    def _consume_until(text: str, symbol: str) -> tuple[str, str]:
        value = "".join(takewhile(lambda c: c != symbol, text))
        tail_idx = len(value) + 1
        return value, text[tail_idx:]

    @classmethod
    def from_arn(cls, arn: str) -> ResourceARN:
        _, arn_tail = ResourceARN._consume_until(arn, ":")
        partition, arn_tail = ResourceARN._consume_until(arn_tail, ":")
        service, arn_tail = ResourceARN._consume_until(arn_tail, ":")
        region, arn_tail = ResourceARN._consume_until(arn_tail, ":")
        account, arn_tail = ResourceARN._consume_until(arn_tail, ":")
        task_type, arn_tail = ResourceARN._consume_until(arn_tail, ":")
        name, arn_tail = ResourceARN._consume_until(arn_tail, ".")
        option = arn_tail
        return cls(
            arn=arn,
            partition=partition,
            service=service,
            region=region,
            account=account,
            task_type=task_type,
            name=name,
            option=option,
        )


class Resource(Component, abc.ABC):
    resource_arn: Final[str]
    partition: Final[str]
    region: Final[str]
    account: Final[str]

    def __init__(self, resource_arn: ResourceARN):
        self.resource_arn = resource_arn.arn
        self.partition = resource_arn.partition
        self.region = resource_arn.region
        self.account = resource_arn.account

    @staticmethod
    def from_resource_arn(arn: str) -> Resource:
        resource_arn = ResourceARN.from_arn(arn)
        if not resource_arn.region:
            resource_arn.region = aws_stack.get_region()
        match resource_arn.service, resource_arn.task_type:
            case "lambda", "function":
                return LambdaResource(resource_arn=resource_arn)
            case "states", "activity":
                return ActivityResource(resource_arn=resource_arn)
            case "states", _:
                return ServiceResource(resource_arn=resource_arn)


class ActivityResource(Resource):
    name: Final[str]

    def __init__(self, resource_arn: ResourceARN):
        super().__init__(resource_arn=resource_arn)
        self.name = resource_arn.name


class LambdaResource(Resource):
    function_name: Final[str]

    def __init__(self, resource_arn: ResourceARN):
        super().__init__(resource_arn=resource_arn)
        self.function_name: str = resource_arn.name


class ServiceResource(Resource):
    service_name: Final[str]
    api_name: Final[str]
    api_action: Final[str]
    condition: Final[Optional[str]]

    def __init__(self, resource_arn: ResourceARN):
        super().__init__(resource_arn=resource_arn)
        self.service_name = resource_arn.task_type

        name_parts = resource_arn.name.split(":")
        if len(name_parts) == 1:
            self.api_name = self.service_name
            self.api_action = resource_arn.name
        elif len(name_parts) > 1:
            self.api_name = name_parts[0]
            self.api_action = name_parts[1]
        else:
            raise RuntimeError(f"Incorrect definition of ResourceArn.name: '{resource_arn.name}'.")

        self.condition = None
        option = resource_arn.option
        if option:
            match option:
                case ResourceCondition.WaitForTaskToken:
                    self.condition = ResourceCondition.WaitForTaskToken
                case "sync":
                    self.condition = ResourceCondition.Sync
                case "sync:2":
                    self.condition = ResourceCondition.Sync2
                case unsupported:
                    raise RuntimeError(f"Unsupported condition '{unsupported}'.")
