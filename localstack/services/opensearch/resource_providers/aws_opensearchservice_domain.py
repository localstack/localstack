# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, TypedDict

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)


class OpenSearchServiceDomainProperties(TypedDict):
    AccessPolicies: Optional[dict]
    AdvancedOptions: Optional[dict]
    AdvancedSecurityOptions: Optional[AdvancedSecurityOptionsInput]
    Arn: Optional[str]
    ClusterConfig: Optional[ClusterConfig]
    CognitoOptions: Optional[CognitoOptions]
    DomainArn: Optional[str]
    DomainEndpoint: Optional[str]
    DomainEndpointOptions: Optional[DomainEndpointOptions]
    DomainEndpoints: Optional[dict]
    DomainName: Optional[str]
    EBSOptions: Optional[EBSOptions]
    EncryptionAtRestOptions: Optional[EncryptionAtRestOptions]
    EngineVersion: Optional[str]
    Id: Optional[str]
    LogPublishingOptions: Optional[dict]
    NodeToNodeEncryptionOptions: Optional[NodeToNodeEncryptionOptions]
    OffPeakWindowOptions: Optional[OffPeakWindowOptions]
    ServiceSoftwareOptions: Optional[ServiceSoftwareOptions]
    SnapshotOptions: Optional[SnapshotOptions]
    SoftwareUpdateOptions: Optional[SoftwareUpdateOptions]
    Tags: Optional[list[Tag]]
    VPCOptions: Optional[VPCOptions]


class ZoneAwarenessConfig(TypedDict):
    AvailabilityZoneCount: Optional[int]


class ClusterConfig(TypedDict):
    DedicatedMasterCount: Optional[int]
    DedicatedMasterEnabled: Optional[bool]
    DedicatedMasterType: Optional[str]
    InstanceCount: Optional[int]
    InstanceType: Optional[str]
    WarmCount: Optional[int]
    WarmEnabled: Optional[bool]
    WarmType: Optional[str]
    ZoneAwarenessConfig: Optional[ZoneAwarenessConfig]
    ZoneAwarenessEnabled: Optional[bool]


class SnapshotOptions(TypedDict):
    AutomatedSnapshotStartHour: Optional[int]


class VPCOptions(TypedDict):
    SecurityGroupIds: Optional[list[str]]
    SubnetIds: Optional[list[str]]


class NodeToNodeEncryptionOptions(TypedDict):
    Enabled: Optional[bool]


class DomainEndpointOptions(TypedDict):
    CustomEndpoint: Optional[str]
    CustomEndpointCertificateArn: Optional[str]
    CustomEndpointEnabled: Optional[bool]
    EnforceHTTPS: Optional[bool]
    TLSSecurityPolicy: Optional[str]


class CognitoOptions(TypedDict):
    Enabled: Optional[bool]
    IdentityPoolId: Optional[str]
    RoleArn: Optional[str]
    UserPoolId: Optional[str]


class MasterUserOptions(TypedDict):
    MasterUserARN: Optional[str]
    MasterUserName: Optional[str]
    MasterUserPassword: Optional[str]


class Idp(TypedDict):
    EntityId: Optional[str]
    MetadataContent: Optional[str]


class SAMLOptions(TypedDict):
    Enabled: Optional[bool]
    Idp: Optional[Idp]
    MasterBackendRole: Optional[str]
    MasterUserName: Optional[str]
    RolesKey: Optional[str]
    SessionTimeoutMinutes: Optional[int]
    SubjectKey: Optional[str]


class AdvancedSecurityOptionsInput(TypedDict):
    AnonymousAuthDisableDate: Optional[str]
    AnonymousAuthEnabled: Optional[bool]
    Enabled: Optional[bool]
    InternalUserDatabaseEnabled: Optional[bool]
    MasterUserOptions: Optional[MasterUserOptions]
    SAMLOptions: Optional[SAMLOptions]


class EBSOptions(TypedDict):
    EBSEnabled: Optional[bool]
    Iops: Optional[int]
    Throughput: Optional[int]
    VolumeSize: Optional[int]
    VolumeType: Optional[str]


class EncryptionAtRestOptions(TypedDict):
    Enabled: Optional[bool]
    KmsKeyId: Optional[str]


class Tag(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


class ServiceSoftwareOptions(TypedDict):
    AutomatedUpdateDate: Optional[str]
    Cancellable: Optional[bool]
    CurrentVersion: Optional[str]
    Description: Optional[str]
    NewVersion: Optional[str]
    OptionalDeployment: Optional[bool]
    UpdateAvailable: Optional[bool]
    UpdateStatus: Optional[str]


class WindowStartTime(TypedDict):
    Hours: Optional[int]
    Minutes: Optional[int]


class OffPeakWindow(TypedDict):
    WindowStartTime: Optional[WindowStartTime]


class OffPeakWindowOptions(TypedDict):
    Enabled: Optional[bool]
    OffPeakWindow: Optional[OffPeakWindow]


class SoftwareUpdateOptions(TypedDict):
    AutoSoftwareUpdateEnabled: Optional[bool]


REPEATED_INVOCATION = "repeated_invocation"


class OpenSearchServiceDomainProvider(ResourceProvider[OpenSearchServiceDomainProperties]):

    TYPE = "AWS::OpenSearchService::Domain"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[OpenSearchServiceDomainProperties],
    ) -> ProgressEvent[OpenSearchServiceDomainProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/DomainName



        Create-only properties:
          - /properties/DomainName

        Read-only properties:
          - /properties/Id
          - /properties/Arn
          - /properties/DomainArn
          - /properties/DomainEndpoint
          - /properties/DomainEndpoints
          - /properties/ServiceSoftwareOptions
          - /properties/AdvancedSecurityOptions/AnonymousAuthDisableDate

        IAM permissions required:
          - es:CreateDomain
          - es:DescribeDomain
          - es:AddTags
          - es:ListTags

        """
        model = request.desired_state
        opensearch_client = request.aws_client_factory.opensearch
        if not request.custom_context.get(REPEATED_INVOCATION):
            # resource is not ready
            # this is the first time this callback is invoked
            request.custom_context[REPEATED_INVOCATION] = True

            # defaults
            domain_name = model.get("DomainName")
            if not domain_name:
                domain_name = util.generate_default_name(
                    request.stack_name, request.logical_resource_id
                ).lower()[0:28]
                model["DomainName"] = domain_name

            properties = util.remove_none_values(model)
            cluster_config = properties.get("ClusterConfig")
            if isinstance(cluster_config, dict):
                # set defaults required for boto3 calls
                cluster_config.setdefault("DedicatedMasterType", "m3.medium.search")
                cluster_config.setdefault("WarmType", "ultrawarm1.medium.search")

                for key in ["DedicatedMasterCount", "InstanceCount", "WarmCount"]:
                    if key in cluster_config and isinstance(cluster_config[key], str):
                        cluster_config[key] = int(cluster_config[key])

            if properties.get("AccessPolicies"):
                properties["AccessPolicies"] = json.dumps(properties["AccessPolicies"])

            if ebs_options := properties.get("EBSOptions"):
                for key in ["Iops", "Throughput", "VolumeSize"]:
                    if key in ebs_options and isinstance(ebs_options[key], str):
                        ebs_options[key] = int(ebs_options[key])

            create_kwargs = {**util.deselect_attributes(properties, ["Tags"])}
            if tags := properties.get("Tags"):
                create_kwargs["TagList"] = tags
            opensearch_client.create_domain(**create_kwargs)
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )
        opensearch_domain = opensearch_client.describe_domain(DomainName=model["DomainName"])
        if opensearch_domain["DomainStatus"]["Processing"] is False:
            # set data
            model["Arn"] = opensearch_domain["DomainStatus"]["ARN"]
            model["Id"] = opensearch_domain["DomainStatus"]["DomainId"]
            model["DomainArn"] = opensearch_domain["DomainStatus"]["ARN"]
            model["DomainEndpoint"] = opensearch_domain["DomainStatus"].get("Endpoint")
            model["DomainEndpoints"] = opensearch_domain["DomainStatus"].get("Endpoints")
            model["ServiceSoftwareOptions"] = opensearch_domain["DomainStatus"].get(
                "ServiceSoftwareOptions"
            )
            model.setdefault("AdvancedSecurityOptions", {})["AnonymousAuthDisableDate"] = (
                opensearch_domain["DomainStatus"]
                .get("AdvancedSecurityOptions", {})
                .get("AnonymousAuthDisableDate")
            )

            return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)
        else:
            return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)

    def read(
        self,
        request: ResourceRequest[OpenSearchServiceDomainProperties],
    ) -> ProgressEvent[OpenSearchServiceDomainProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - es:DescribeDomain
          - es:ListTags
        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[OpenSearchServiceDomainProperties],
    ) -> ProgressEvent[OpenSearchServiceDomainProperties]:
        """
        Delete a resource

        IAM permissions required:
          - es:DeleteDomain
          - es:DescribeDomain
        """
        opensearch_client = request.aws_client_factory.opensearch
        # TODO the delete is currently synchronous;
        #   if this changes, we should also reflect the OperationStatus here
        opensearch_client.delete_domain(DomainName=request.previous_state["DomainName"])
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model={})

    def update(
        self,
        request: ResourceRequest[OpenSearchServiceDomainProperties],
    ) -> ProgressEvent[OpenSearchServiceDomainProperties]:
        """
        Update a resource

        IAM permissions required:
          - es:UpdateDomain
          - es:UpgradeDomain
          - es:DescribeDomain
          - es:AddTags
          - es:RemoveTags
          - es:ListTags
        """
        raise NotImplementedError
