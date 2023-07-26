from __future__ import annotations

import abc
from typing import Final, Optional, TypedDict

from localstack.services.stepfunctions.asl.component.component import Component
from localstack.utils.aws import aws_stack


class ResourceCondition(str):
    WaitForTaskToken = "waitForTaskToken"
    Sync = "sync"


class ResourceARN(TypedDict):
    partition: str
    service: str
    region: str
    account: str
    task_type: str
    name: str


class Resource(Component, abc.ABC):
    def __init__(self, resource_arn: str, partition: str, region: str, account: str):
        self.resource_arn: Final[str] = resource_arn
        self.partition: Final[str] = partition
        self.region: Final[str] = region
        self.account: Final[str] = account

    @staticmethod
    def parse_resource_arn(arn: str) -> ResourceARN:
        cmps: list[str] = arn.split(":")
        return ResourceARN(
            partition=cmps[1],
            service=cmps[2],
            region=cmps[3],
            account=cmps[4],
            task_type=cmps[5],
            name=cmps[6],
        )

    @staticmethod
    def from_resource_arn(arn: str) -> Resource:
        resource_arn: ResourceARN = Resource.parse_resource_arn(arn)
        if not resource_arn["region"]:
            resource_arn["region"] = aws_stack.get_region()
        match resource_arn["service"], resource_arn["task_type"]:
            case "lambda", "function":
                return LambdaResource(
                    resource_arn=arn,
                    partition=resource_arn["partition"],
                    region=resource_arn["region"],
                    account=resource_arn["account"],
                    function_name=resource_arn["name"],
                )
            case "states", "activity":
                return ActivityResource(
                    resource_arn=arn,
                    partition=resource_arn["partition"],
                    region=resource_arn["region"],
                    account=resource_arn["account"],
                    name=resource_arn["name"],
                )
            case "states", service_name:
                return ServiceResource(
                    resource_arn=arn,
                    partition=resource_arn["partition"],
                    region=resource_arn["region"],
                    account=resource_arn["account"],
                    service_name=service_name,  # noqa
                    api_name=resource_arn["name"],
                )


class ActivityResource(Resource):
    def __init__(self, resource_arn: str, partition: str, region: str, account: str, name: str):
        super().__init__(
            resource_arn=resource_arn, partition=partition, region=region, account=account
        )
        self.name: str = name


class LambdaResource(Resource):
    def __init__(
        self, resource_arn: str, partition: str, region: str, account: str, function_name: str
    ):
        super().__init__(
            resource_arn=resource_arn, partition=partition, region=region, account=account
        )
        self.function_name: str = function_name


class ServiceResource(Resource):
    service_name: Final[str]
    api_name: Final[str]
    api_action: Final[str]
    condition: Final[Optional[str]]

    def __init__(
        self,
        resource_arn: str,
        partition: str,
        region: str,
        account: str,
        service_name: str,
        api_name: str,
    ):
        super().__init__(
            resource_arn=resource_arn, partition=partition, region=region, account=account
        )
        self.service_name = service_name
        self.api_name = api_name

        arn_parts = resource_arn.split(":")
        tail_part = arn_parts[-1]
        tail_parts = tail_part.split(".")
        self.api_action = tail_parts[0]

        self.condition = None
        if len(tail_parts) > 1:
            match tail_parts[-1]:
                case "waitForTaskToken":
                    self.condition = ResourceCondition.WaitForTaskToken
                case "sync":
                    self.condition = ResourceCondition.Sync
                case unsupported:
                    raise RuntimeError(f"Unsupported condition '{unsupported}'.")
