from abc import ABC
from datetime import datetime, timezone
from typing import Dict

from moto.ec2 import ec2_backends
from moto.ec2.exceptions import InvalidVpcEndPointIdError

from localstack.aws.api import RequestContext, ServiceException, handler
from localstack.aws.api.ec2 import (
    Boolean,
    CreateVpcEndpointServiceConfigurationResult,
    CurrencyCodeValues,
    DeleteVpcEndpointsRequest,
    DeleteVpcEndpointsResult,
    DescribeReservedInstancesOfferingsRequest,
    DescribeReservedInstancesOfferingsResult,
    DescribeReservedInstancesRequest,
    DescribeReservedInstancesResult,
    DescribeVpcEndpointServicesResult,
    Ec2Api,
    FilterList,
    InstanceType,
    Integer,
    ModifyVpcEndpointResult,
    OfferingClassType,
    OfferingTypeValues,
    PricingDetail,
    PurchaseReservedInstancesOfferingRequest,
    PurchaseReservedInstancesOfferingResult,
    RecurringCharge,
    RecurringChargeFrequency,
    ReservedInstances,
    ReservedInstancesOffering,
    ReservedInstanceState,
    RIProductDescription,
    ServiceConfiguration,
    String,
    TagSpecificationList,
    Tenancy,
    ValueStringList,
    VpcEndpoint,
    VpcEndpointId,
    VpcEndpointRouteTableIdList,
    VpcEndpointSecurityGroupIdList,
    VpcEndpointSubnetIdList,
    scope,
)
from localstack.services import moto
from localstack.services.generic_proxy import RegionBackend
from localstack.utils.strings import long_uid, short_uid
from localstack.utils.tagging import TaggingService


class Ec2Backend(RegionBackend):
    vpc_endpoints: Dict[str, VpcEndpoint]
    vpc_endpoint_service_configurations: Dict[str, ServiceConfiguration]

    TAGS = TaggingService()

    def __init__(self):
        self.vpc_endpoints = {}
        self.vpc_endpoint_service_configurations = {}


class InvalidVpcEndpointIdException(ServiceException):
    pass


class Ec2Provider(Ec2Api, ABC):
    @handler("DescribeReservedInstancesOfferings", expand=False)
    def describe_reserved_instances_offerings(
        self,
        context: RequestContext,
        describe_reserved_instances_offerings_request: DescribeReservedInstancesOfferingsRequest,
    ) -> DescribeReservedInstancesOfferingsResult:
        return DescribeReservedInstancesOfferingsResult(
            ReservedInstancesOfferings=[
                ReservedInstancesOffering(
                    AvailabilityZone="eu-central-1a",
                    Duration=2628000,
                    FixedPrice=0.0,
                    InstanceType=InstanceType.t2_small,
                    ProductDescription=RIProductDescription.Linux_UNIX,
                    ReservedInstancesOfferingId=long_uid(),
                    UsagePrice=0.0,
                    CurrencyCode=CurrencyCodeValues.USD,
                    InstanceTenancy=Tenancy.default,
                    Marketplace=True,
                    PricingDetails=[PricingDetail(Price=0.0, Count=3)],
                    RecurringCharges=[
                        RecurringCharge(Amount=0.25, Frequency=RecurringChargeFrequency.Hourly)
                    ],
                    Scope=scope.Availability_Zone,
                )
            ]
        )

    @handler("DescribeReservedInstances", expand=False)
    def describe_reserved_instances(
        self,
        context: RequestContext,
        describe_reserved_instances_request: DescribeReservedInstancesRequest,
    ) -> DescribeReservedInstancesResult:
        return DescribeReservedInstancesResult(
            ReservedInstances=[
                ReservedInstances(
                    AvailabilityZone="eu-central-1a",
                    Duration=2628000,
                    End=datetime(2016, 6, 30, tzinfo=timezone.utc),
                    FixedPrice=0.0,
                    InstanceCount=2,
                    InstanceType=InstanceType.t2_small,
                    ProductDescription=RIProductDescription.Linux_UNIX,
                    ReservedInstancesId=long_uid(),
                    Start=datetime(2016, 1, 1, tzinfo=timezone.utc),
                    State=ReservedInstanceState.active,
                    UsagePrice=0.05,
                    CurrencyCode=CurrencyCodeValues.USD,
                    InstanceTenancy=Tenancy.default,
                    OfferingClass=OfferingClassType.standard,
                    OfferingType=OfferingTypeValues.Partial_Upfront,
                    RecurringCharges=[
                        RecurringCharge(Amount=0.05, Frequency=RecurringChargeFrequency.Hourly)
                    ],
                    Scope=scope.Availability_Zone,
                )
            ]
        )

    @handler("PurchaseReservedInstancesOfferings", expand=False)
    def purchase_reserved_instances_offering(
        self,
        context: RequestContext,
        purchase_reserved_instances_offerings_request: PurchaseReservedInstancesOfferingRequest,
    ) -> PurchaseReservedInstancesOfferingResult:
        return PurchaseReservedInstancesOfferingResult(
            ReservedInstancesId=long_uid(),
        )

    @handler("DeleteVpcEndpoints", expand=False)
    def delete_vpc_endpoints(
        self, context: RequestContext, delete_vpc_endpoints_request: DeleteVpcEndpointsRequest
    ) -> DeleteVpcEndpointsResult:
        return moto.call_moto(context)

    @handler("CreateVpcEndpointServiceConfiguration")
    def create_vpc_endpoint_service_configuration(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        acceptance_required: Boolean = None,
        private_dns_name: String = None,
        network_load_balancer_arns: ValueStringList = None,
        gateway_load_balancer_arns: ValueStringList = None,
        client_token: String = None,
        tag_specifications: TagSpecificationList = None,
    ) -> CreateVpcEndpointServiceConfigurationResult:
        region = Ec2Backend.get()

        service_id = short_uid()
        service_config = ServiceConfiguration(
            ServiceId=service_id,
            AcceptanceRequired=acceptance_required,
            PrivateDnsName=private_dns_name,
            NetworkLoadBalancerArns=network_load_balancer_arns,
            GatewayLoadBalancerArns=gateway_load_balancer_arns,
        )
        region.vpc_endpoint_service_configurations[service_id] = service_config

        return CreateVpcEndpointServiceConfigurationResult(
            ServiceConfiguration=service_config,
        )

    # ModifyVpcEndpoint is not implemented in moto
    @handler("ModifyVpcEndpoint")
    def modify_vpc_endpoint(
        self,
        context: RequestContext,
        vpc_endpoint_id: VpcEndpointId,
        dry_run: Boolean = None,
        reset_policy: Boolean = None,
        policy_document: String = None,
        add_route_table_ids: VpcEndpointRouteTableIdList = None,
        remove_route_table_ids: VpcEndpointRouteTableIdList = None,
        add_subnet_ids: VpcEndpointSubnetIdList = None,
        remove_subnet_ids: VpcEndpointSubnetIdList = None,
        add_security_group_ids: VpcEndpointSecurityGroupIdList = None,
        remove_security_group_ids: VpcEndpointSecurityGroupIdList = None,
        private_dns_enabled: Boolean = None,
    ) -> ModifyVpcEndpointResult:
        backend = ec2_backends.get()
        vpc_endpoint = backend.vpc_end_points.get(vpc_endpoint_id)

        if not vpc_endpoint:
            raise InvalidVpcEndPointIdError(vpc_endpoint_id)

        vpc_endpoint["PolicyDocument"] = policy_document or vpc_endpoint["PolicyDocument"]

        vpc_endpoint["RouteTableIds"].extend(add_route_table_ids)
        vpc_endpoint["RouteTableIds"] = [
            id_ for id_ in vpc_endpoint["RouteTableIds"] if id_ not in remove_route_table_ids
        ]

        vpc_endpoint["SubnetIds"].extend(add_subnet_ids)
        vpc_endpoint["SubnetIds"] = [
            id_ for id_ in vpc_endpoint["SubnetIds"] if id_ not in remove_subnet_ids
        ]

        vpc_endpoint["PrivateDnsEnabled"] = (
            vpc_endpoint["PrivateDnsEnabled"]
            if private_dns_enabled is None
            else private_dns_enabled
        )

        return ModifyVpcEndpointResult(Return=True)

    @handler("DescribeVpcEndpointServices")
    def describe_vpc_endpoint_services(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        service_names: ValueStringList = None,
        filters: FilterList = None,
        max_results: Integer = None,
        next_token: String = None,
    ) -> DescribeVpcEndpointServicesResult:
        # TODO@viren
        pass
