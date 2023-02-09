import re
from abc import ABC
from datetime import datetime, timezone

from botocore.parsers import ResponseParserError
from moto.core.utils import camelcase_to_underscores, underscores_to_camelcase
from moto.ec2.exceptions import InvalidVpcEndPointIdError
from moto.ec2.models import SubnetBackend, TransitGatewayAttachmentBackend
from moto.ec2.models.launch_templates import LaunchTemplate as MotoLaunchTemplate
from moto.ec2.models.subnets import Subnet

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.ec2 import (
    AvailabilityZone,
    Boolean,
    CreateLaunchTemplateRequest,
    CreateLaunchTemplateResult,
    CreateSubnetRequest,
    CreateSubnetResult,
    CreateTransitGatewayRequest,
    CreateTransitGatewayResult,
    CurrencyCodeValues,
    DescribeAvailabilityZonesRequest,
    DescribeAvailabilityZonesResult,
    DescribeReservedInstancesOfferingsRequest,
    DescribeReservedInstancesOfferingsResult,
    DescribeReservedInstancesRequest,
    DescribeReservedInstancesResult,
    DescribeSubnetsRequest,
    DescribeSubnetsResult,
    DescribeTransitGatewaysRequest,
    DescribeTransitGatewaysResult,
    Ec2Api,
    InstanceType,
    ModifyLaunchTemplateRequest,
    ModifyLaunchTemplateResult,
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
from localstack.services.ec2.exceptions import (
    InvalidLaunchTemplateIdError,
    InvalidLaunchTemplateNameError,
    MissingParameterError,
)
from localstack.services.ec2.models import get_ec2_backend
from localstack.services.moto import call_moto
from localstack.utils.aws import aws_stack
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
        backend = get_ec2_backend(context.account_id, context.region)

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
        backend = get_ec2_backend(context.account_id, context.region)

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

            backend = get_ec2_backend(context.account_id, context.region)

            # fix setting subnet attributes currently not supported upstream
            subnet_id = request["SubnetId"]
            host_type = request.get("PrivateDnsHostnameTypeOnLaunch")
            a_record_on_launch = request.get("EnableResourceNameDnsARecordOnLaunch")
            aaaa_record_on_launch = request.get("EnableResourceNameDnsAAAARecordOnLaunch")
            enable_dns64 = request.get("EnableDns64")

            if host_type:
                attr_name = camelcase_to_underscores("PrivateDnsNameOptionsOnLaunch")
                value = {"HostnameType": host_type}
                backend.modify_subnet_attribute(subnet_id, attr_name, value)
            ## explicitly checking None value as this could contain a False value
            if aaaa_record_on_launch is not None:
                attr_name = camelcase_to_underscores("PrivateDnsNameOptionsOnLaunch")
                value = {"EnableResourceNameDnsAAAARecord": aaaa_record_on_launch["Value"]}
                backend.modify_subnet_attribute(subnet_id, attr_name, value)
            if a_record_on_launch is not None:
                attr_name = camelcase_to_underscores("PrivateDnsNameOptionsOnLaunch")
                value = {"EnableResourceNameDnsARecord": a_record_on_launch["Value"]}
                backend.modify_subnet_attribute(subnet_id, attr_name, value)
            if enable_dns64 is not None:
                attr_name = camelcase_to_underscores("EnableDns64")
                backend.modify_subnet_attribute(subnet_id, attr_name, enable_dns64["Value"])

    @handler("CreateSubnet", expand=False)
    def create_subnet(
        self, context: RequestContext, request: CreateSubnetRequest
    ) -> CreateSubnetResult:
        response = call_moto(context)
        backend = get_ec2_backend(context.account_id, context.region)
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
                backend = get_ec2_backend(context.account_id, context.region)
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
        backend = get_ec2_backend(context.account_id, context.region)
        # add additional/missing attributes in subnet responses
        for subnet in result.get("Subnets", []):
            subnet_obj = backend.subnets[subnet["AvailabilityZone"]].get(subnet["SubnetId"])
            for attr in ADDITIONAL_SUBNET_ATTRS:
                if hasattr(subnet_obj, attr):
                    attr_name = first_char_to_upper(underscores_to_camelcase(attr))
                    if attr_name not in subnet:
                        subnet[attr_name] = getattr(subnet_obj, attr)
        return result

    @handler("CreateTransitGateway", expand=False)
    def create_transit_gateway(
        self,
        context: RequestContext,
        request: CreateTransitGatewayRequest,
    ) -> CreateTransitGatewayResult:
        result = call_moto(context)
        backend = get_ec2_backend(context.account_id, context.region)
        transit_gateway_id = result["TransitGateway"]["TransitGatewayId"]
        transit_gateway = backend.transit_gateways.get(transit_gateway_id)
        result.get("TransitGateway").get("Options").update(transit_gateway.options)
        return result

    @handler("DescribeTransitGateways", expand=False)
    def describe_transit_gateways(
        self,
        context: RequestContext,
        request: DescribeTransitGatewaysRequest,
    ) -> DescribeTransitGatewaysResult:
        result = call_moto(context)
        backend = get_ec2_backend(context.account_id, context.region)
        for transit_gateway in result.get("TransitGateways", []):
            transit_gateway_id = transit_gateway["TransitGatewayId"]
            tgw = backend.transit_gateways.get(transit_gateway_id)
            transit_gateway["Options"].update(tgw.options)
        return result

    @handler("CreateLaunchTemplate", expand=False)
    def create_launch_template(
        self,
        context: RequestContext,
        request: CreateLaunchTemplateRequest,
    ) -> CreateLaunchTemplateResult:

        # parameter validation
        if not request["LaunchTemplateData"]:
            raise MissingParameterError(parameter="LaunchTemplateData")

        name = request["LaunchTemplateName"]
        if len(name) < 3 or len(name) > 128 or not re.fullmatch(r"[a-zA-Z0-9.\-_()/]*", name):
            raise InvalidLaunchTemplateNameError()

        return call_moto(context)

    @handler("ModifyLaunchTemplate", expand=False)
    def modify_launch_template(
        self,
        context: RequestContext,
        request: ModifyLaunchTemplateRequest,
    ) -> ModifyLaunchTemplateResult:

        backend = get_ec2_backend(context.account_id, context.region)
        template_id = (
            request["LaunchTemplateId"]
            or backend.launch_template_name_to_ids[request["LaunchTemplateName"]]
        )
        template: MotoLaunchTemplate = backend.launch_templates[template_id]

        # check if defaultVersion exists
        if request["DefaultVersion"]:
            try:
                template.versions[int(request["DefaultVersion"]) - 1]
            except IndexError:
                raise InvalidLaunchTemplateIdError()

        template.default_version_number = int(request["DefaultVersion"])

        client = aws_stack.connect_to_service("ec2")
        retrieved_template = client.describe_launch_templates(LaunchTemplateIds=[template.id])

        result: ModifyLaunchTemplateResult = {
            "LaunchTemplate": retrieved_template["LaunchTemplates"][0],
        }

        return result


@patch(SubnetBackend.modify_subnet_attribute)
def modify_subnet_attribute(fn, self, subnet_id, attr_name, attr_value):
    subnet = self.get_subnet(subnet_id)
    if attr_name in ADDITIONAL_SUBNET_ATTRS:
        # private dns name options on launch contains dict with keys EnableResourceNameDnsARecord and EnableResourceNameDnsAAAARecord, HostnameType
        if attr_name == "private_dns_name_options_on_launch":
            if hasattr(subnet, attr_name):
                getattr(subnet, attr_name).update(attr_value)
                return
            else:
                setattr(subnet, attr_name, attr_value)
                return
        setattr(subnet, attr_name, attr_value)
        return
    return fn(self, subnet_id, attr_name, attr_value)


@patch(Subnet.get_filter_value)
def get_filter_value(fn, self, filter_name):
    if filter_name in (
        "ipv6CidrBlockAssociationSet.associationId",
        "ipv6-cidr-block-association.association-id",
    ):
        return self.ipv6_cidr_block_associations
    return fn(self, filter_name)


@patch(TransitGatewayAttachmentBackend.delete_transit_gateway_vpc_attachment)
def delete_transit_gateway_vpc_attachment(fn, self, transit_gateway_attachment_id):
    transit_gateway_attachment = self.transit_gateway_attachments.get(transit_gateway_attachment_id)
    transit_gateway_attachment.state = "deleted"
    return transit_gateway_attachment
