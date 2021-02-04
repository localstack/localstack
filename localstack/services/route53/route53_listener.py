from localstack.utils.common import parse_request_data, short_uid, to_str
import xmltodict
from requests.models import Response
from six.moves.urllib.parse import urlparse
from localstack.utils.persistence import PersistingProxyListener
from localstack.services.generic_proxy import RegionBackend


# TODO import RegionBackend
class Route53Backend(RegionBackend):
    def __init__(self):
        # maps association ID to details
        self.vpc_hosted_zone_associations = {}
        self.domains = {}


class ProxyListenerRoute53(PersistingProxyListener):
    def api_name(self):
        return 'route53'

    def forward_request(self, method, path, data, headers):
        parsed_url = urlparse(path)
        action = parsed_url.path.split('/')[2]

        if path.endswith('/associatevpc'):
            path_parts = path.split('/')
            zone_id = path_parts[3]
            req_data = xmltodict.parse(to_str(data))
            root = req_data['AssociateVPCWithHostedZoneRequest']
            vpc_id = root['VPC']['VPCId']
            # vpc_region = root['VPC']['VPCRegion']

            region_details = Route53Backend.get()
            assoc_id = short_uid()
            if zone_id in region_details.vpc_hosted_zone_associations.keys():
                region_details.vpc_hosted_zone_associations[zone_id][vpc_id] = assoc_id
            else:
                region_details.vpc_hosted_zone_associations[zone_id] = {
                    vpc_id: assoc_id
                }

            response = Response()
            associate_response = {
                'AssociateVPCWithHostedZoneResponse': {
                    'ChangeInfo': {
                        'Id': assoc_id,
                        'Status': 'INSYNC',
                        'SubmittedAt': '2010-09-10T01:36:41.958Z'
                    }
                }
            }
            body = xmltodict.unparse(associate_response)
            response._content = body
            response.status_code = 200
            print(body)
            return response

        if method == 'GET' and parsed_url.path.endswith('/hostedzonesbyvpc'):
            # todo
            print()

        if action == 'change':
            response = Response()
            if method == 'GET':
                resource_id = parsed_url.path.split('/')[-1]
                change_response = {
                    'GetChangeResponse': {
                        'ChangeInfo': {
                            'Id': resource_id,
                            'Status': 'INSYNC',
                            'SubmittedAt': '2010-09-10T01:36:41.958Z'
                        }
                    }
                }

                body = xmltodict.unparse(change_response)
                response._content = body
                response.status_code = 200
            return response

        return True

    def return_response(self, method, path, data, headers, response, request_handler):
        print(response)
        print(response._content)
        return super().return_response(method, path, data, headers, response, request_handler=request_handler)


# instantiate listener
UPDATE_ROUTE53 = ProxyListenerRoute53()
