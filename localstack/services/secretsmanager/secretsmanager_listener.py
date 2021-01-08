from localstack.utils.persistence import PersistingProxyListener
from localstack.utils.aws.aws_responses import MessageConversion


class ProxyListenerSecretsManager(PersistingProxyListener):
    def api_name(self):
        return 'secretsmanager'

    def return_response(self, method, path, data, headers, response):
        super(ProxyListenerSecretsManager, self).return_response(method, path, data, headers, response)
        if response.content:
            return MessageConversion.fix_account_id(response)


UPDATE_SECRETSMANAGER = ProxyListenerSecretsManager()
