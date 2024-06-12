from functools import cached_property

from rolo.gateway import Gateway

from localstack.aws.app import LocalstackAwsGateway
from localstack.runtime.components import BaseComponents


class AwsComponents(BaseComponents):
    """
    Runtime components specific to the AWS emulator.
    """

    name = "aws"

    @cached_property
    def gateway(self) -> Gateway:
        # FIXME: the ServiceManager should be reworked to be more generic, and then become part of the
        #  components
        from localstack.services.plugins import SERVICE_PLUGINS

        return LocalstackAwsGateway(SERVICE_PLUGINS)
