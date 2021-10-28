import re

import xmltodict
from six.moves.urllib.parse import urlparse

from localstack import constants
from localstack.services.generic_proxy import RegionBackend
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import requests_response
from localstack.utils.common import parse_request_data, short_uid, timestamp_millis, to_str
from localstack.utils.persistence import PersistingProxyListener

PATH_PREFIX = "/2013-04-01"
PATH_DELEGATION_SETS = r"%s/delegationset(/(.+))?" % PATH_PREFIX
XMLNS_ROUTE53 = "https://route53.amazonaws.com/doc/2013-04-01/"


class Route53Backend(RegionBackend):
    def __init__(self):
        # maps zone ID to association details
        self.vpc_hosted_zone_associations = {}
        # maps delegation set ID to reusable delegation set details
        self.reusable_delegation_sets = {}


class ProxyListenerRoute53(PersistingProxyListener):
    def api_name(self):
        return "route53"

    def forward_request(self, method, path, data, headers):
        parsed_url = urlparse(path)
        action = parsed_url.path.split("/")[2]

        if method == "GET" and action == "change":
            resource_id = parsed_url.path.split("/")[-1]
            change_response = {
                "GetChangeResponse": {
                    "ChangeInfo": {
                        "Id": resource_id,
                        "Status": "INSYNC",
                        "SubmittedAt": timestamp_millis(),
                    }
                }
            }
            body = xmltodict.unparse(change_response)
            response = requests_response(body)
            return response

        return True

    def return_response(self, method, path, data, headers, response):
        if response.status_code < 400 or response.status_code >= 500:
            return

        updated_response = None

        if path.endswith("/associatevpc") or path.endswith("/disassociatevpc"):
            updated_response = handle_associate_vpc_request(method, path, data)

        if method == "GET" and "/hostedzonesbyvpc" in path:
            updated_response = handle_hosted_zones_by_vpc_request(method, path, data)

        match = not updated_response and re.match(PATH_DELEGATION_SETS, path)
        if match:
            updated_response = handle_delegation_sets_request(match, method, data)

        if not isinstance(updated_response, dict):
            return updated_response
        updated_response[list(updated_response.keys())[0]]["@xmlns"] = XMLNS_ROUTE53
        body = xmltodict.unparse(updated_response)
        return requests_response(body)


def handle_delegation_sets_request(match, method, data):
    region_details = Route53Backend.get()
    set_id = match.group(2)
    if method == "GET":
        if set_id:
            result = region_details.reusable_delegation_sets.get(set_id)
            if not result:
                return 404
            return {"GetReusableDelegationSetResponse": {"DelegationSet": result}}
        reusable_sets_list = list(region_details.reusable_delegation_sets.values())
        result = {
            "ListReusableDelegationSetsResponse": {
                "IsTruncated": False,
            }
        }
        if len(reusable_sets_list) > 0:
            result["ListReusableDelegationSetsResponse"]["DelegationSets"] = {
                "DelegationSet": reusable_sets_list
            }
        return result
    if method == "POST":
        req_data = xmltodict.parse(to_str(data))
        req_data = req_data.get("CreateReusableDelegationSetRequest")
        req_data.pop("@xmlns", None)
        req_data["Id"] = short_uid()
        region_details.reusable_delegation_sets[req_data["Id"]] = req_data
        return {"CreateReusableDelegationSetResponse": {"DelegationSet": req_data}}
    if method == "DELETE":
        existing = region_details.reusable_delegation_sets.pop(set_id, None)
        if not existing:
            return 404
        return {"DeleteReusableDelegationSetResponse": {}}


def handle_hosted_zones_by_vpc_request(method, path, data):
    def _zone(z):
        zone_id = z["HostedZoneId"]
        hosted_zone = client.get_hosted_zone(Id=zone_id).get("HostedZone", {})
        result = {
            "HostedZoneId": zone_id,
            "Name": hosted_zone.get("Name"),
            "Owner": {"OwningAccount": constants.TEST_AWS_ACCOUNT_ID},
        }
        return result

    region_details = Route53Backend.get()
    client = aws_stack.connect_to_service("route53")
    req_data = parse_request_data(method, path, data)
    vpc_id = req_data.get("vpcid")
    zone_details = region_details.vpc_hosted_zone_associations
    result = [
        _zone(z) for z_list in zone_details.values() for z in z_list if z["VPC"]["VPCId"] == vpc_id
    ]
    return {"ListHostedZonesByVPCResponse": {"HostedZoneSummaries": {"HostedZoneSummary": result}}}


def handle_associate_vpc_request(method, path, data):
    is_associate = path.endswith("/associatevpc")
    region_details = Route53Backend.get()
    path_parts = path.lstrip("/").split("/")
    zone_id = path_parts[2]
    req_data = xmltodict.parse(to_str(data))
    zone_details = region_details.vpc_hosted_zone_associations.get(zone_id) or []
    if is_associate:
        assoc_id = short_uid()
        zone_data = req_data.get("AssociateVPCWithHostedZoneRequest", {})
        zone_data["Id"] = assoc_id
        zone_data["HostedZoneId"] = zone_id
        zone_details.append(zone_data)
        response_entry = {
            "ChangeInfo": {
                "Id": assoc_id,
                "Status": "INSYNC",
                "SubmittedAt": timestamp_millis(),
            }
        }
    else:

        def _match(z):
            return z["HostedZoneId"] == zone_id and z["VPC"]["VPCId"] == zone_data["VPC"]["VPCId"]

        zone_data = req_data.get("DisassociateVPCFromHostedZoneRequest", {})
        response_entry = [z for z in zone_details if _match(z)]
        zone_details = [z for z in zone_details if not _match(z)]
        if not response_entry:
            return 404
        response_entry = response_entry[0]

    region_details.vpc_hosted_zone_associations[zone_id] = zone_details

    response_tag = "%sVPCWithHostedZoneResponse" % ("Associate" if is_associate else "Disassociate")
    return {response_tag: response_entry}


# instantiate listener
UPDATE_ROUTE53 = ProxyListenerRoute53()
