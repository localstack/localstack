import xmltodict
from six.moves.urllib.parse import urlparse
from localstack import constants
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid, to_str, timestamp_millis, parse_request_data
from localstack.utils.persistence import PersistingProxyListener
from localstack.services.generic_proxy import RegionBackend
from localstack.utils.aws.aws_responses import requests_response


class Route53Backend(RegionBackend):
    def __init__(self):
        # maps zone ID to association details
        self.vpc_hosted_zone_associations = {}


class ProxyListenerRoute53(PersistingProxyListener):
    def api_name(self):
        return 'route53'

    def forward_request(self, method, path, data, headers):
        parsed_url = urlparse(path)
        action = parsed_url.path.split('/')[2]

        if action == 'change':
            if method == 'GET':
                resource_id = parsed_url.path.split('/')[-1]
                change_response = {
                    'GetChangeResponse': {
                        'ChangeInfo': {
                            'Id': resource_id,
                            'Status': 'INSYNC',
                            'SubmittedAt': timestamp_millis()
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

        region_details = Route53Backend.get()

        is_associate = path.endswith('/associatevpc')
        if is_associate or path.endswith('/disassociatevpc'):
            path_parts = path.lstrip('/').split('/')
            zone_id = path_parts[2]
            req_data = xmltodict.parse(to_str(data))
            zone_details = region_details.vpc_hosted_zone_associations.get(zone_id) or []
            if is_associate:
                assoc_id = short_uid()
                zone_data = req_data.get('AssociateVPCWithHostedZoneRequest', {})
                zone_data['Id'] = assoc_id
                zone_data['HostedZoneId'] = zone_id
                zone_details.append(zone_data)
                response_entry = {
                    'ChangeInfo': {
                        'Id': assoc_id,
                        'Status': 'INSYNC',
                        'SubmittedAt': timestamp_millis()
                    }
                }
            else:
                def _match(z):
                    return z['HostedZoneId'] == zone_id and z['VPC']['VPCId'] == zone_data['VPC']['VPCId']
                zone_data = req_data.get('DisassociateVPCFromHostedZoneRequest', {})
                response_entry = [z for z in zone_details if _match(z)]
                zone_details = [z for z in zone_details if not _match(z)]
                if not response_entry:
                    return 404
                response_entry = response_entry[0]

            region_details.vpc_hosted_zone_associations[zone_id] = zone_details

            response_tag = '%sVPCWithHostedZoneResponse' % ('Associate' if is_associate else 'Disassociate')
            response = {
                response_tag: response_entry
            }
            body = xmltodict.unparse(response)
            response = requests_response(body)
            return response

        if '/hostedzonesbyvpc' in path and method == 'GET':
            def _zone(z):
                zone_id = z['HostedZoneId']
                hosted_zone = client.get_hosted_zone(Id=zone_id).get('HostedZone', {})
                result = {
                    'HostedZoneId': zone_id,
                    'Name': hosted_zone.get('Name'),
                    'Owner': {'OwningAccount': constants.TEST_AWS_ACCOUNT_ID}
                }
                return result
            client = aws_stack.connect_to_service('route53')
            req_data = parse_request_data(method, path, data)
            vpc_id = req_data.get('vpcid')
            zone_details = region_details.vpc_hosted_zone_associations
            result = [_zone(z) for z_list in zone_details.values() for z in z_list if z['VPC']['VPCId'] == vpc_id]
            response = {'ListHostedZonesByVPCResponse': {'HostedZoneSummaries': {'HostedZoneSummary': result}}}
            body = xmltodict.unparse(response)
            response = requests_response(body)
            return response


# instantiate listener
UPDATE_ROUTE53 = ProxyListenerRoute53()
