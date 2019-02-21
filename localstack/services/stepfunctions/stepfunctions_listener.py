import logging
from localstack.services.generic_proxy import ProxyListener

LOG = logging.getLogger(__name__)


class ProxyListenerStepFunctions(ProxyListener):

    def forward_request(self, method, path, data, headers):
        LOG.debug('StepFunctions request:', method, path, data)
        return True


# instantiate listener
UPDATE_STEPFUNCTIONS = ProxyListenerStepFunctions()
