# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

from pathlib import Path
from typing import Optional, TypedDict

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)


class CloudFormationWaitConditionHandleProperties(TypedDict):
    Id: Optional[str]


REPEATED_INVOCATION = "repeated_invocation"


class CloudFormationWaitConditionHandleProvider(
    ResourceProvider[CloudFormationWaitConditionHandleProperties]
):
    TYPE = "AWS::CloudFormation::WaitConditionHandle"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[CloudFormationWaitConditionHandleProperties],
    ) -> ProgressEvent[CloudFormationWaitConditionHandleProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/Id





        Read-only properties:
          - /properties/Id



        """
        # TODO: properly test this and fix s3 bucket usage
        model = request.desired_state

        s3 = request.aws_client_factory.s3
        region = s3.meta.region_name

        bucket = f"cloudformation-waitcondition-{region}"
        waitcondition_url = s3.generate_presigned_url(
            "put_object", Params={"Bucket": bucket, "Key": request.stack_id}
        )
        model["Id"] = waitcondition_url

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def read(
        self,
        request: ResourceRequest[CloudFormationWaitConditionHandleProperties],
    ) -> ProgressEvent[CloudFormationWaitConditionHandleProperties]:
        """
        Fetch resource information


        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[CloudFormationWaitConditionHandleProperties],
    ) -> ProgressEvent[CloudFormationWaitConditionHandleProperties]:
        """
        Delete a resource


        """
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model={})

    def update(
        self,
        request: ResourceRequest[CloudFormationWaitConditionHandleProperties],
    ) -> ProgressEvent[CloudFormationWaitConditionHandleProperties]:
        """
        Update a resource


        """
        raise NotImplementedError
