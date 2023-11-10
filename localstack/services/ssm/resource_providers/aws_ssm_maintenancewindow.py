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


class SSMMaintenanceWindowProperties(TypedDict):
    AllowUnassociatedTargets: Optional[bool]
    Cutoff: Optional[int]
    Duration: Optional[int]
    Name: Optional[str]
    Schedule: Optional[str]
    Description: Optional[str]
    EndDate: Optional[str]
    Id: Optional[str]
    ScheduleOffset: Optional[int]
    ScheduleTimezone: Optional[str]
    StartDate: Optional[str]
    Tags: Optional[list[Tag]]


class Tag(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


REPEATED_INVOCATION = "repeated_invocation"


class SSMMaintenanceWindowProvider(ResourceProvider[SSMMaintenanceWindowProperties]):
    TYPE = "AWS::SSM::MaintenanceWindow"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[SSMMaintenanceWindowProperties],
    ) -> ProgressEvent[SSMMaintenanceWindowProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/Id

        Required properties:
          - AllowUnassociatedTargets
          - Cutoff
          - Schedule
          - Duration
          - Name



        Read-only properties:
          - /properties/Id



        """
        model = request.desired_state
        ssm_client = request.aws_client_factory.ssm

        params = util.select_attributes(
            model,
            [
                "AllowUnassociatedTargets",
                "Cutoff",
                "Duration",
                "Name",
                "Schedule",
                "ScheduleOffset",
                "ScheduleTimezone",
                "StartDate",
                "EndDate",
                "Description",
                "Tags",
            ],
        )

        response = ssm_client.create_maintenance_window(**params)
        model["Id"] = response["WindowId"]

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def read(
        self,
        request: ResourceRequest[SSMMaintenanceWindowProperties],
    ) -> ProgressEvent[SSMMaintenanceWindowProperties]:
        """
        Fetch resource information


        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[SSMMaintenanceWindowProperties],
    ) -> ProgressEvent[SSMMaintenanceWindowProperties]:
        """
        Delete a resource


        """
        model = request.desired_state
        ssm_client = request.aws_client_factory.ssm

        ssm_client.delete_maintenance_window(WindowId=model["Id"])

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def update(
        self,
        request: ResourceRequest[SSMMaintenanceWindowProperties],
    ) -> ProgressEvent[SSMMaintenanceWindowProperties]:
        """
        Update a resource


        """
        raise NotImplementedError
