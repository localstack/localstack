from localstack.services.generic_proxy import ProxyListener


class ProxyListenerS3Control(ProxyListener):
    pass
# instantiate listener
UPDATE_S3CONTROL = ProxyListenerS3Control()
