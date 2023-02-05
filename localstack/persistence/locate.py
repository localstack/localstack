import importlib
import logging
from typing import Any, Optional

from .core import StateVisitor

LOG = logging.getLogger(__name__)


class ReflectionStateLocator:
    """
    Implementation of the StateVisitable protocol that uses reflection to visit and collect anything that hold state
    for a service, based on the assumption that AccountRegionBundle and BackendDict are stored in a predictable
    location with a predictable naming.
    """

    provider: Any

    def __init__(self, provider: Optional[Any] = None, service: Optional[str] = None):
        self.provider = provider
        self.service = service or provider.service

    def accept_state_visitor(self, visitor: StateVisitor):
        # needed for services like cognito-idp
        service_name: str = self.service.replace("-", "_")

        def _visit_modules(_modules):
            for _module, _attribute in _modules:
                _attribute = self._load_attribute_from_module(_module, _attribute)
                if _attribute is not None:
                    LOG.debug("visiting attribute %s in module %s", _attribute, _module)
                    visitor.visit(_attribute)

        match service_name:
            # lambda is a special case in package and module naming
            # the store attribute is `awslambda_stores` in `localstack.services.awslambda.lambda_models`
            case "lambda":
                modules = [
                    ("localstack.services.awslambda.lambda_models", "awslambda_stores"),
                    ("moto.awslambda.models", "lambda_backends"),
                ]
                _visit_modules(modules)
            case "apigatewayv2":
                modules = [
                    ("localstack_ext.services.apigateway.models", "apigatewayv2_stores"),
                    ("moto.apigatewayv2.models", "apigatewayv2_backends"),
                ]
                _visit_modules(modules)
            case "cloudformation":
                modules = [
                    ("localstack.services.cloudformation.stores", "cloudformation_stores"),
                    ("moto.cloudformation.models", "cloudformation_backends"),
                ]
                _visit_modules(modules)
            case "ce":
                modules = [
                    ("localstack_ext.services.costexplorer.models", "ce_stores"),
                    ("moto.ce.models", "ce_backends"),
                ]
                _visit_modules(modules)
            case _:
                # try to load AccountRegionBundle from predictable location
                attribute_name = f"{service_name}_stores"
                module_name = f"localstack_ext.services.{service_name}.models"

                # it first looks for a module in ext; eventually, it falls back to community
                attribute = self._load_attribute_from_module(module_name, attribute_name)
                if attribute is None:
                    module_name = f"localstack.services.{service_name}.models"
                    attribute = self._load_attribute_from_module(module_name, attribute_name)

                if attribute is not None:
                    LOG.debug("Visiting attribute %s in module %s", attribute_name, module_name)
                    visitor.visit(attribute)

                # try to load BackendDict from predictable location
                module_name = f"moto.{service_name}.models"
                attribute_name = f"{service_name}_backends"
                attribute = self._load_attribute_from_module(module_name, attribute_name)

                if attribute is None and "_" in attribute_name:
                    # some services like application_autoscaling do have a backend without the underscore
                    service_name_tmp = service_name.replace("_", "")
                    module_name = f"moto.{service_name_tmp}.models"
                    attribute_name = f"{service_name_tmp}_backends"
                    attribute = self._load_attribute_from_module(module_name, attribute_name)

                if attribute is not None:
                    LOG.debug("visiting attribute %s in module %s", attribute_name, module_name)
                    visitor.visit(attribute)

    @staticmethod
    def _load_attribute_from_module(module_name: str, attribute_name: str) -> Any | None:
        """
        Attempts at getting an attribute from a given module.
        :return the attribute or None, if the attribute can't be found
        """
        try:
            module = importlib.import_module(module_name)
            return getattr(module, attribute_name)
        except (ModuleNotFoundError, AttributeError) as e:
            LOG.debug(
                'unable to get attribute "%s" for module "%s": "%s"', attribute_name, module_name, e
            )
            return None
