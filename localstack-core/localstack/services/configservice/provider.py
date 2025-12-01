from localstack.aws.api.config import ConfigApi
from localstack.state import StateVisitor


class ConfigProvider(ConfigApi):
    def accept_state_visitor(self, visitor: StateVisitor):
        from moto.config.models import config_backends

        visitor.visit(config_backends)
