from localstack.utils.persistence import PersistingProxyListener


class ProxyListenerSecretsManager(PersistingProxyListener):
    def api_name(self):
        return 'secretsmanager'


UPDATE_SECRETSMANAGER = ProxyListenerSecretsManager()
