# instantiate listener
from localstack.utils.persistence import PersistingProxyListener

# backend port (configured in swf_starter.py on startup)
PORT_SWF_BACKEND = None


class ProxyListenerSWF(PersistingProxyListener):
    def api_name(self):
        return "swf"


UPDATE_SWF = ProxyListenerSWF()
