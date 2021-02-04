import json
import logging
from requests.models import Request
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str
from localstack.utils.persistence import PersistingProxyListener
from localstack.utils.aws.aws_responses import MessageConversion

LOG = logging.getLogger(__name__)


class ProxyListenerSecretsManager(PersistingProxyListener):
    def api_name(self):
        return 'secretsmanager'

    def forward_request(self, method, path, data, headers):
        data = json.loads(to_str(data or '{}'))
        secret_id = data.get('SecretId') or ''
        if ':' in secret_id:
            parts = secret_id.split(':')
            if parts[3] != aws_stack.get_region():
                LOG.info('Unexpected request region %s for secret "%s"' % (aws_stack.get_region(), secret_id))
            # secret ARN ends with "-<randomId>" which we remove in the request for upstream compatibility
            data['SecretId'] = parts[-1].rpartition('-')[0]
            data = json.dumps(data)
            return Request(data=data, headers=headers, method=method)
        return True

    def return_response(self, method, path, data, headers, response):
        super(ProxyListenerSecretsManager, self).return_response(method, path, data, headers, response)
        if response.content:
            return MessageConversion.fix_account_id(response)


UPDATE_SECRETSMANAGER = ProxyListenerSecretsManager()
