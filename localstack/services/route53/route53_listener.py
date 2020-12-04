import xmltodict
from requests.models import Response
from six.moves.urllib.parse import urlparse
from localstack.utils.persistence import PersistingProxyListener


class ProxyListenerRoute53(PersistingProxyListener):
    def api_name(self):
        return 'route53'

    def forward_request(self, method, path, data, headers):
        parsed_url = urlparse(path)
        action = parsed_url.path.split('/')[2]

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


# instantiate listener
UPDATE_ROUTE53 = ProxyListenerRoute53()
