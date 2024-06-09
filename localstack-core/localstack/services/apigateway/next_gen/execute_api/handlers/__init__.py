from rolo.gateway import CompositeHandler

from .integration import IntegrationHandler
from .integration_request import IntegrationRequestHandler
from .integration_response import IntegrationResponseHandler
from .method_request import MethodRequestHandler
from .method_response import MethodResponseHandler
from .tempory_global import GlobalTemporaryHandler

global_temporary_handler = GlobalTemporaryHandler()
preprocess_request = CompositeHandler()
method_request_handler = MethodRequestHandler()
integration_request_handler = IntegrationRequestHandler()
integration_handler = IntegrationHandler()
integration_response_handler = IntegrationResponseHandler()
method_response_handler = MethodResponseHandler()
