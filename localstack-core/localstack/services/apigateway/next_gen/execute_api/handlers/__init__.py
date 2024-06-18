from rolo.gateway import CompositeHandler

from .gateway_exception import GatewayExceptionHandler
from .integration import IntegrationHandler
from .integration_request import IntegrationRequestHandler
from .integration_response import IntegrationResponseHandler
from .legacy import LegacyHandler
from .method_request import MethodRequestHandler
from .method_response import MethodResponseHandler
from .parse import InvocationRequestParser

legacy_handler = LegacyHandler()
parse_request = InvocationRequestParser()
preprocess_request = CompositeHandler()
method_request_handler = MethodRequestHandler()
integration_request_handler = IntegrationRequestHandler()
integration_handler = IntegrationHandler()
integration_response_handler = IntegrationResponseHandler()
method_response_handler = MethodResponseHandler()
gateway_exception_handler = GatewayExceptionHandler()
