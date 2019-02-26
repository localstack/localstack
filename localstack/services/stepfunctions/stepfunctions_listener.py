import logging
from localstack.services.generic_proxy import ProxyListener

LOG = logging.getLogger(__name__)


class ProxyListenerStepFunctions(ProxyListener):

    # TODO: listener methods currently disabled

    def forward_request_DISABLED(self, method, path, data, headers):
        LOG.debug('StepFunctions request: %s %s %s', method, path, data)
        return True

    def return_response_DISABLED(self, method, path, data, headers, response):
        LOG.debug('StepFunctions response: %s %s %s %s', method, path, response.status_code, response.content)


# instantiate listener
UPDATE_STEPFUNCTIONS = ProxyListenerStepFunctions()
