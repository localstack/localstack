import logging
import re

import xmltodict
from moto.ec2 import models as ec2_models
from moto.ec2.responses import security_groups, vpcs

from localstack import config
from localstack.services.infra import start_moto_server
from localstack.utils.common import long_uid, short_uid

LOG = logging.getLogger(__name__)

REGEX_FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL

GATEWAY_SERVICES = ["s3", "dynamodb"]

XMLNS_EC2 = "http://ec2.amazonaws.com/doc/2016-11-15/"


def patch_ec2():

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
                LOG.debug('Unsupported VPC endpoint service filter "%s"', filter["Name"])
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
                LOG.debug('Unsupported VPC endpoint service filter "%s"', filter["Name"])
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
            values = filter["Value"]
            for val in values:
                if val is None:
                    break
                filter["Values"].append(val)
        return search_filters

    vpcs.VPCs._parse_search_filters = _parse_search_filters


def start_ec2(port=None, asynchronous=False, update_listener=None):
    patch_ec2()
    port = port or config.service_port("ec2")

    return start_moto_server(
        "ec2",
        port,
        name="EC2",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
