from __future__ import annotations

import abc
from itertools import takewhile
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


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


class Resource(EvalComponent, abc.ABC):
    class ResourceOutput:
        resource_arn: Final[str]
        partition: Final[str]
        region: Final[str]
        account: Final[str]

        def __init__(self, resource_arn: str, partition: str, region: str, account: str):
            self.resource_arn = resource_arn
            self.partition = partition
            self.region = region
            self.account = account

    _region: Final[str]
    _account: Final[str]
    resource_arn: Final[str]
    partition: Final[str]

    def __init__(self, resource_arn: ResourceARN):
        self._region = resource_arn.region
        self._account = resource_arn.account
        self.resource_arn = resource_arn.arn
        self.partition = resource_arn.partition

    @staticmethod
    def from_resource_arn(arn: str) -> Resource:
        resource_arn = ResourceARN.from_arn(arn)
        match resource_arn.service, resource_arn.task_type:
            case "lambda", "function":
                return LambdaResource(resource_arn=resource_arn)
            case "states", "activity":
                return ActivityResource(resource_arn=resource_arn)
            case "states", _:
                return ServiceResource(resource_arn=resource_arn)

    def _build_resource(self, env: Environment) -> Resource.ResourceOutput:
        region = self._region if self._region else env.aws_execution_details.region
        account = self._account if self._account else env.aws_execution_details.account
        return Resource.ResourceOutput(
            resource_arn=self.resource_arn,
            partition=self.partition,
            region=region,
            account=account,
        )

    def _eval_body(self, env: Environment) -> None:
        resource_output = self._build_resource(env=env)
        env.stack.append(resource_output)


class ActivityResource(Resource):
    class ActivityResourceOutput(Resource.ResourceOutput):
        name: Final[str]

        def __init__(self, resource_arn: str, partition: str, region: str, account: str, name: str):
            super().__init__(
                resource_arn=resource_arn, partition=partition, region=region, account=account
            )
            self.name = name

    name: Final[str]

    def __init__(self, resource_arn: ResourceARN):
        super().__init__(resource_arn=resource_arn)
        self.name = resource_arn.name

    def _build_resource(self, env: Environment) -> Resource.ResourceOutput:
        resource_output: Resource.ResourceOutput = super()._build_resource(env=env)
        activity_resource_output = ActivityResource.ActivityResourceOutput(
            **vars(resource_output), name=self.name
        )
        return activity_resource_output


class LambdaResource(Resource):
    class LambdaResourceOutput(Resource.ResourceOutput):
        function_name: Final[str]

        def __init__(
            self, resource_arn: str, partition: str, region: str, account: str, function_name: str
        ):
            super().__init__(
                resource_arn=resource_arn, partition=partition, region=region, account=account
            )
            self.function_name = function_name

    function_name: Final[str]

    def __init__(self, resource_arn: ResourceARN):
        super().__init__(resource_arn=resource_arn)
        self.function_name = resource_arn.name

    def _build_resource(self, env: Environment) -> Resource.ResourceOutput:
        resource_output: Resource.ResourceOutput = super()._build_resource(env=env)
        lambda_resource_output = LambdaResource.LambdaResourceOutput(
            **vars(resource_output), function_name=self.function_name
        )
        return lambda_resource_output


class ServiceResource(Resource):
    class ServiceResourceOutput(Resource.ResourceOutput):
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
            api_action: str,
            condition: Optional[str],
        ):
            super().__init__(
                resource_arn=resource_arn, partition=partition, region=region, account=account
            )
            self.service_name = service_name
            self.api_name = api_name
            self.api_action = api_action
            self.condition = condition

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

    def _build_resource(self, env: Environment) -> Resource.ResourceOutput:
        resource_output: Resource.ResourceOutput = super()._build_resource(env=env)
        lambda_resource_output = ServiceResource.ServiceResourceOutput(
            **vars(resource_output),
            service_name=self.service_name,
            api_name=self.api_name,
            api_action=self.api_action,
            condition=self.condition,
        )
        return lambda_resource_output
