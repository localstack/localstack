from abc import ABC
from datetime import datetime, timezone

from botocore.parsers import ResponseParserError
from moto.core.utils import camelcase_to_underscores, underscores_to_camelcase
from moto.ec2 import ec2_backends
from moto.ec2.exceptions import InvalidVpcEndPointIdError
from moto.ec2.models import SubnetBackend

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.ec2 import (
    AvailabilityZone,
    Boolean,
    CreateSubnetRequest,
    CreateSubnetResult,
    CurrencyCodeValues,
    DescribeAvailabilityZonesRequest,
    DescribeAvailabilityZonesResult,
    DescribeReservedInstancesOfferingsRequest,
    DescribeReservedInstancesOfferingsResult,
    DescribeReservedInstancesRequest,
    DescribeReservedInstancesResult,
    DescribeSubnetsRequest,
    DescribeSubnetsResult,
    Ec2Api,
    InstanceType,
    ModifySubnetAttributeRequest,
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
    RevokeSecurityGroupEgressRequest,
    RevokeSecurityGroupEgressResult,
    RIProductDescription,
    String,
    Tenancy,
    VpcEndpointId,
    VpcEndpointRouteTableIdList,
    VpcEndpointSecurityGroupIdList,
    VpcEndpointSubnetIdList,
    scope,
)
from localstack.services.moto import call_moto
from localstack.utils.patch import patch
from localstack.utils.strings import first_char_to_upper, long_uid

# additional subnet attributes not yet supported upstream
ADDITIONAL_SUBNET_ATTRS = ("private_dns_name_options_on_launch", "enable_dns64")


class Ec2Provider(Ec2Api, ABC):
    @handler("DescribeAvailabilityZones", expand=False)
    def describe_availability_zones(
        self,
        context: RequestContext,
        describe_availability_zones_request: DescribeAvailabilityZonesRequest,
    ) -> DescribeAvailabilityZonesResult:
        backend = ec2_backends[context.region]

        availability_zones = []
        zone_names = describe_availability_zones_request.get("ZoneNames")
        if zone_names:
            for zone in zone_names:
                zone_detail = backend.get_zone_by_name(zone)
                if zone_detail:
                    availability_zones.append(
                        AvailabilityZone(
                            State="available",
                            Messages=[],
                            RegionName=zone_detail.region_name,
                            ZoneName=zone_detail.name,
                            ZoneId=zone_detail.zone_id,
                        )
                    )

            return DescribeAvailabilityZonesResult(AvailabilityZones=availability_zones)

        return call_moto(context)

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

    @handler("PurchaseReservedInstancesOffering", expand=False)
    def purchase_reserved_instances_offering(
        self,
        context: RequestContext,
        purchase_reserved_instances_offerings_request: PurchaseReservedInstancesOfferingRequest,
    ) -> PurchaseReservedInstancesOfferingResult:
        return PurchaseReservedInstancesOfferingResult(
            ReservedInstancesId=long_uid(),
        )

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
        backend = ec2_backends[context.region]

        vpc_endpoint = backend.vpc_end_points.get(vpc_endpoint_id)
        if not vpc_endpoint:
            raise InvalidVpcEndPointIdError(vpc_endpoint_id)

        if policy_document is not None:
            vpc_endpoint.policy_document = policy_document

        if add_route_table_ids is not None:
            vpc_endpoint.route_table_ids.extend(add_route_table_ids)

        if remove_route_table_ids is not None:
            vpc_endpoint.route_table_ids = [
                id_ for id_ in vpc_endpoint.route_table_ids if id_ not in remove_route_table_ids
            ]

        if add_subnet_ids is not None:
            vpc_endpoint.subnet_ids.extend(add_subnet_ids)

        if remove_subnet_ids is not None:
            vpc_endpoint.subnet_ids = [
                id_ for id_ in vpc_endpoint.subnet_ids if id_ not in remove_subnet_ids
            ]

        if private_dns_enabled is not None:
            vpc_endpoint.private_dns_enabled = private_dns_enabled

        return ModifyVpcEndpointResult(Return=True)

    @handler("ModifySubnetAttribute", expand=False)
    def modify_subnet_attribute(
        self, context: RequestContext, request: ModifySubnetAttributeRequest
    ) -> None:
        try:
            return call_moto(context)
        except Exception as e:
            if not isinstance(e, ResponseParserError) and "InvalidParameterValue" not in str(e):
                raise
            # fix setting subnet attributes currently not supported upstream
            backend = ec2_backends[context.region]
            subnet_id = request["SubnetId"]
            host_type = request.get("PrivateDnsHostnameTypeOnLaunch")
            if host_type:
                attr_name = camelcase_to_underscores("PrivateDnsNameOptionsOnLaunch")
                value = {"HostnameType": host_type}
                backend.modify_subnet_attribute(subnet_id, attr_name, value)
            enable_dns64 = request.get("EnableDns64")
            if enable_dns64:
                attr_name = camelcase_to_underscores("EnableDns64")
                backend.modify_subnet_attribute(subnet_id, attr_name, enable_dns64)

    @handler("CreateSubnet", expand=False)
    def create_subnet(
        self, context: RequestContext, request: CreateSubnetRequest
    ) -> CreateSubnetResult:
        response = call_moto(context)
        backend = ec2_backends[context.region]
        subnet_id = response["Subnet"]["SubnetId"]
        host_type = request.get("PrivateDnsHostnameTypeOnLaunch", "ip-name")
        attr_name = camelcase_to_underscores("PrivateDnsNameOptionsOnLaunch")
        value = {"HostnameType": host_type}
        backend.modify_subnet_attribute(subnet_id, attr_name, value)
        return response

    @handler("RevokeSecurityGroupEgress", expand=False)
    def revoke_security_group_egress(
        self,
        context: RequestContext,
        revoke_security_group_egress_request: RevokeSecurityGroupEgressRequest,
    ) -> RevokeSecurityGroupEgressResult:
        try:
            return call_moto(context)
        except Exception as e:
            if "specified rule does not exist" in str(e):
                backend = ec2_backends[context.region]
                group_id = revoke_security_group_egress_request["GroupId"]
                group = backend.get_security_group_by_name_or_id(group_id)
                if group and not group.egress_rules:
                    return RevokeSecurityGroupEgressResult(Return=True)
            raise

    @handler("DescribeSubnets", expand=False)
    def describe_subnets(
        self,
        context: RequestContext,
        request: DescribeSubnetsRequest,
    ) -> DescribeSubnetsResult:
        result = call_moto(context)
        backend = ec2_backends[context.region]
        # add additional/missing attributes in subnet responses
        for subnet in result.get("Subnets", []):
            subnet_obj = backend.subnets[subnet["AvailabilityZone"]][subnet["SubnetId"]]
            for attr in ADDITIONAL_SUBNET_ATTRS:
                if hasattr(subnet_obj, attr):
                    attr_name = first_char_to_upper(underscores_to_camelcase(attr))
                    if attr_name not in subnet:
                        subnet[attr_name] = getattr(subnet_obj, attr)
        return result


@patch(SubnetBackend.modify_subnet_attribute)
def modify_subnet_attribute(fn, self, subnet_id, attr_name, attr_value):
    subnet = self.get_subnet(subnet_id)
    if attr_name in ADDITIONAL_SUBNET_ATTRS:
        setattr(subnet, attr_name, attr_value)
        return
    return fn(self, subnet_id, attr_name, attr_value)
