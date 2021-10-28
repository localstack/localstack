import logging
import re

import xmltodict
from moto.ec2 import models as ec2_models
from moto.ec2.exceptions import InvalidPermissionNotFoundError
from moto.ec2.responses import security_groups, vpcs
from moto.ec2.responses.reserved_instances import ReservedInstances

from localstack import config
from localstack.services.infra import start_moto_server
from localstack.utils.common import long_uid, short_uid

LOG = logging.getLogger(__name__)

REGEX_FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL

GATEWAY_SERVICES = ["s3", "dynamodb"]

XMLNS_EC2 = "http://ec2.amazonaws.com/doc/2016-11-15/"


def patch_ec2():
    def patch_revoke_security_group_egress(backend):
        revoke_security_group_egress_orig = backend.revoke_security_group_egress

        def revoke_security_group_egress(*args, **kwargs):
            try:
                return revoke_security_group_egress_orig(*args, **kwargs)
            except InvalidPermissionNotFoundError:
                # this can happen, as CidrIpv6 is not yet supported by moto
                if args[4] == []:
                    return "_ignore_"

        return revoke_security_group_egress

    def patch_delete_nat_gateway(backend):
        def delete_nat_gateway(nat_gateway_id):
            gateway = backend.nat_gateways.get(nat_gateway_id)
            if gateway:
                gateway.state = "deleted"

        return delete_nat_gateway

    for region, backend in ec2_models.ec2_backends.items():
        backend.revoke_security_group_egress = patch_revoke_security_group_egress(backend)
        backend.delete_nat_gateway = patch_delete_nat_gateway(backend)

    # TODO Implement Reserved Instance backend
    # https://github.com/localstack/localstack/issues/2435
    def describe_reserved_instances_offerings(self):
        template = self.response_template(DESCRIBE_RESERVED_INSTANCES_OFFERINGS_RESPONSE)
        return template.render({})

    def purchase_reserved_instances_offering(self):
        template = self.response_template(PURCHASE_RESERVED_INSTANCES_OFFERINGS_RESPONSE)
        return template.render({})

    def describe_reserved_instances(self):
        template = self.response_template(DESCRIBE_RESERVED_INSTANCES_RESPONSE)
        return template.render({})

    ReservedInstances.describe_reserved_instances_offerings = describe_reserved_instances_offerings
    ReservedInstances.purchase_reserved_instances_offering = purchase_reserved_instances_offering
    ReservedInstances.describe_reserved_instances = describe_reserved_instances

    # make sure we report groupName only for default VPCs (i.e., omit for custom VPCs with vpc_id)
    search = r"</groupId>\s*<groupName>\{\{\s*source_group.name\s*\}\}</groupName>"
    replace = r"</groupId>{% if not group.vpc_id %}<groupName>{{ source_group.name }}</groupName>{% endif %}"
    security_groups.DESCRIBE_SECURITY_GROUPS_RESPONSE = re.sub(
        search,
        replace,
        security_groups.DESCRIBE_SECURITY_GROUPS_RESPONSE,
        flags=REGEX_FLAGS,
    )

    # bootstrap default VPC endpoint services
    def describe_vpc_endpoint_services(self):
        if not hasattr(self.ec2_backend, "_vpc_endpoint_services"):
            service_entries = []
            region = self.ec2_backend.region_name
            availability_zones = ec2_models.EC2Backend.describe_availability_zones(self.ec2_backend)
            for service_id, _ in config.SERVICE_PORTS.items():
                service_name = "com.amazonaws.%s.%s" % (region, service_id)
                dns_name = "%s.%s.amazonaws.com" % (service_id, region)
                stypes = ["Interface"] + (["Gateway"] if service_id in GATEWAY_SERVICES else [])
                entry = {
                    "serviceName": service_name,
                    "serviceId": "vpce-svc-%s" % short_uid(),
                    "serviceType": [{"serviceType": stype} for stype in stypes],
                    "availabilityZones": [z.name for z in availability_zones],
                    "owner": "amazon",
                    "baseEndpointDnsNames": [],
                    "privateDnsName": dns_name,
                    "privateDnsNames": [{"PrivateDnsName": dns_name}],
                    "vpcEndpointPolicySupported": True,
                    "acceptanceRequired": False,
                    "managesVpcEndpoints": False,
                    "tags": [],
                    "privateDnsNameVerificationState": "verified",
                }
                service_entries.append(entry)
            self.ec2_backend._vpc_endpoint_services = service_entries

        # construct result
        search_filters = self._parse_search_filters()
        search_names = self._get_multi_param("ServiceName")
        services = self.ec2_backend._vpc_endpoint_services
        if search_names:
            services = [s for s in services if s["serviceName"] in search_names]
        for filter in search_filters:
            if filter["Name"] == "service-name":
                services = [s for s in services if s["serviceName"] in filter["Values"]]
            elif filter["Name"] == "service-type":
                services = [
                    s
                    for s in services
                    if any(
                        v in [stype["serviceType"] for stype in s["serviceType"]]
                        for v in filter["Values"]
                    )
                ]
            else:
                LOG.debug('Unsupported VPC endpoint service filter "%s"' % filter["Name"])
        service_names = [s["serviceName"] for s in services]
        services = [{**s, "serviceType": {"item": s["serviceType"]}} for s in services]
        services = [{**s, "availabilityZones": {"item": s["availabilityZones"]}} for s in services]
        services = [{**s, "tagSet": {"item": s["tags"]}} for s in services]
        result = {
            "DescribeVpcEndpointServicesResponse": {
                "@xmlns": XMLNS_EC2,
                "serviceNameSet": {"item": service_names},
                "serviceDetailSet": {"item": services},
                "requestId": long_uid(),
            }
        }
        result = xmltodict.unparse(result)
        return result

    vpcs.VPCs.describe_vpc_endpoint_services = describe_vpc_endpoint_services

    # DescribePrefixLists API

    def describe_prefix_lists(self):
        if not hasattr(self.ec2_backend, "_prefix_lists"):
            entries = self.ec2_backend._prefix_lists = []
            for service_id in GATEWAY_SERVICES:
                region = self.ec2_backend.region_name
                service_name = "com.amazonaws.%s.%s" % (region, service_id)
                entry = {
                    "prefixListName": service_name,
                    "prefixListId": "pl-%s" % short_uid(),
                    "cidrSet": {"item": ["52.219.80.0/20"]},
                }
                entries.append(entry)
        entries = self.ec2_backend._prefix_lists
        search_filters = self._parse_search_filters()
        for filter in search_filters:
            if filter["Name"] == "prefix-list-name":
                entries = [s for s in entries if s["prefixListName"] in filter["Values"]]
            else:
                LOG.debug('Unsupported VPC endpoint service filter "%s"' % filter["Name"])
        result = {
            "DescribePrefixListsResponse": {
                "@xmlns": XMLNS_EC2,
                "prefixListSet": {"item": entries},
                "requestId": long_uid(),
            }
        }
        result = xmltodict.unparse(result)
        return result

    if not hasattr(vpcs.VPCs, "describe_prefix_lists"):
        vpcs.VPCs.describe_prefix_lists = describe_prefix_lists

    # util function to parse search filter params

    def _parse_search_filters(self):
        search_filters = self._get_multi_param("Filter")
        for filter in search_filters:
            filter["Values"] = []
            for i in range(1, 100):
                val = filter.get("Value.%s" % i)
                if val is None:
                    break
                filter["Values"].append(val)
        return search_filters

    vpcs.VPCs._parse_search_filters = _parse_search_filters

    # add ability to modify VPC endpoints

    def modify_vpc_endpoint(self):
        endpoint_id = self._get_param("VpcEndpointId")
        endpoint = self.ec2_backend.vpc_end_points.get(endpoint_id)
        if not endpoint:
            return "", {}, 404

        policy_doc = self._get_param("PolicyDocument")
        dns_enabled = self._get_bool_param("PrivateDnsEnabled")
        add_table_ids = self._get_multi_param("AddRouteTableId")
        remove_table_ids = self._get_multi_param("RemoveRouteTableId")
        add_subnet_ids = self._get_multi_param("AddSubnetId")
        remove_subnet_ids = self._get_multi_param("RemoveSubnetId")
        # TODO: fix SecurityGroupIds in backend model!
        # add_secgrp_ids = self._get_multi_param('AddSecurityGroupId')
        # remove_secgrp_ids = self._get_multi_param('RemoveSecurityGroupId')
        endpoint.route_table_ids.extend(add_table_ids)
        endpoint.route_table_ids = [
            i for i in endpoint.route_table_ids if i not in remove_table_ids
        ]
        endpoint.subnet_ids.extend(add_subnet_ids)
        endpoint.subnet_ids = [i for i in endpoint.subnet_ids if i not in remove_subnet_ids]
        endpoint.policy_document = policy_doc or endpoint.policy_document
        endpoint.private_dns_enabled = (
            endpoint.private_dns_enabled if dns_enabled is None else dns_enabled
        )
        result = {
            "ModifyVpcEndpointResponse": {
                "@xmlns": XMLNS_EC2,
                "return": "true",
                "requestId": long_uid(),
            }
        }
        result = xmltodict.unparse(result)
        return result

    vpcs.VPCs.modify_vpc_endpoint = modify_vpc_endpoint

    def create_vpc_endpoint_service_configuration(self):
        configs = getattr(self.ec2_backend, "vpc_endpoint_service_configurations", {})
        self.ec2_backend.vpc_endpoint_service_configurations = configs
        dns_name = self._get_param("PrivateDnsName")
        lb_arns = self._get_multi_param("NetworkLoadBalancerArn")
        gw_arns = self._get_multi_param("GatewayLoadBalancerArn")
        tags = self._get_multi_param("TagSpecification")
        tags = (tags or {}).get("Tags")
        service_id = short_uid()
        entry = {
            "serviceId": service_id,
            "privateDnsName": dns_name,
            "networkLoadBalancerArns": lb_arns,
            "gatewayLoadBalancerArns": gw_arns,
            "Tags": tags,
        }
        configs[service_id] = entry
        result = {
            "CreateVpcEndpointServiceConfigurationResponse": {
                "@xmlns": XMLNS_EC2,
                "serviceConfiguration": entry,
            }
        }
        result = xmltodict.unparse(result)
        return result

    if not hasattr(vpcs.VPCs, "delete_vpc_endpoints"):
        vpcs.VPCs.create_vpc_endpoint_service_configuration = (
            create_vpc_endpoint_service_configuration
        )

    def delete_vpc_endpoints(self):
        vpc_endpoints_ids = self._get_multi_param("VpcEndpointId")
        for ep_id in vpc_endpoints_ids:
            self.ec2_backend.vpc_end_points.pop(ep_id, None)
        result = {"DeleteVpcEndpointsResponse": {"@xmlns": XMLNS_EC2, "unsuccessful": []}}
        return xmltodict.unparse(result)

    if not hasattr(vpcs.VPCs, "delete_vpc_endpoints"):
        vpcs.VPCs.delete_vpc_endpoints = delete_vpc_endpoints


def start_ec2(port=None, asynchronous=False, update_listener=None):
    patch_ec2()
    port = port or config.PORT_EC2

    return start_moto_server(
        "ec2",
        port,
        name="EC2",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )


DESCRIBE_RESERVED_INSTANCES_OFFERINGS_RESPONSE = (
    """
<DescribeReservedInstancesOfferingsResponse xmlns="%s">
  <requestId>2bc7dafa-dafd-4257-bdf9-c0814EXAMPLE</requestId>
  <reservedInstancesOfferingsSet>
    <item>
      <reservedInstancesOfferingId>a6ce8269-7b8c-42cd-a7f5-0841cEXAMPLE</reservedInstancesOfferingId>
      <instanceType>t2.small</instanceType>
      <availabilityZone>us-east-1a</availabilityZone>
      <duration>2332800</duration>
      <fixedPrice>0.0</fixedPrice>
      <usagePrice>0.0</usagePrice>
      <productDescription>Linux/UNIX</productDescription>
      <instanceTenancy>default</instanceTenancy>
      <currencyCode>USD</currencyCode>
      <offeringType>Heavy Utilization</offeringType>
      <recurringCharges>
           <item>
                <frequency>Hourly</frequency>
                <amount>0.19</amount>
            </item>
      </recurringCharges>
      <marketplace>true</marketplace>
      <pricingDetailsSet>
        <item>
          <price>0.0</price>
          <count>3</count>
        </item>
      </pricingDetailsSet>
       <offeringClass>standard</offeringClass>
      <scope>Availability Zone</scope>
    </item>
  </reservedInstancesOfferingsSet>
</DescribeReservedInstancesOfferingsResponse>"""
    % XMLNS_EC2
)

PURCHASE_RESERVED_INSTANCES_OFFERINGS_RESPONSE = (
    """
<PurchaseReservedInstancesOfferingResponse xmlns="%s">
  <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
  <reservedInstancesId>e5a2ff3b-7d14-494f-90af-0b5d0EXAMPLE</reservedInstancesId>
</PurchaseReservedInstancesOfferingResponse>"""
    % XMLNS_EC2
)

DESCRIBE_RESERVED_INSTANCES_RESPONSE = (
    """
<DescribeReservedInstancesResponse xmlns="%s">
   <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
   <reservedInstancesSet>
      <item>
         <reservedInstancesId>e5a2ff3b-7d14-494f-90af-0b5d0EXAMPLE</reservedInstancesId>
         <instanceType>m1.xlarge</instanceType>
         <availabilityZone>us-east-1a</availabilityZone>
         <start>2015-07-14T11:00:00Z</start>
         <end>2016-07-13T12:00:00Z</end>
         <duration>31536000</duration>
         <fixedPrice>0.0</fixedPrice>
         <usagePrice>0.034</usagePrice>
         <instanceCount>2</instanceCount>
         <productDescription>Linux/UNIX (Amazon VPC)</productDescription>
         <state>active</state>
         <instanceTenancy>default</instanceTenancy>
         <currencyCode>USD</currencyCode>
         <offeringType>Partial Upfront</offeringType>
         <recurringCharges>
                  <item>
                        <frequency>Hourly</frequency>
                        <amount>0.05</amount>
                  </item>
         </recurringCharges>
         <offeringClass>standard</offeringClass>
         <scope>AvailabilityZone</scope>
      </item>
   </reservedInstancesSet>
</DescribeReservedInstancesResponse>"""
    % XMLNS_EC2
)
