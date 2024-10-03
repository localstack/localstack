import logging
import os
import sys
from pathlib import Path

import yaml
from plux import Plugin

from localstack import config
from localstack.runtime import hooks
from localstack.utils.files import rm_rf
from localstack.utils.ssl import get_cert_pem_file_path

LOG = logging.getLogger(__name__)


@hooks.on_infra_start()
def deprecation_warnings() -> None:
    LOG.debug("Checking for the usage of deprecated community features and configs...")
    from localstack.deprecations import log_deprecation_warnings

    log_deprecation_warnings()


@hooks.on_infra_start(should_load=lambda: config.REMOVE_SSL_CERT)
def delete_cached_certificate():
    LOG.debug("Removing the cached local SSL certificate")
    target_file = get_cert_pem_file_path()
    rm_rf(target_file)


class OASPlugin(Plugin):
    """
    This plugin allows to register an arbitrary number of OpenAPI specs, e.g., the spec for the public endpoints
    of localstack.core.
    The OpenAPIValidator handler uses (as opt-in) all the collected specs to validate the requests and the responses
    to these public endpoints.

    An OAS plugin assumes the following directory layout.

    my_package
    ├── sub_package
    │   ├── __init__.py       <-- spec file
    │   ├── openapi.yaml
    │   └── plugins.py        <-- plugins
    ├── plugins.py            <-- plugins
    └── openapi.yaml          <-- spec file

    Each package can have its own OpenAPI yaml spec which is loaded by the correspondent plugin in plugins.py
    You can simply create a plugin like the following:

    class MyPackageOASPlugin(OASPlugin):
        name = "my_package"

    The only convention is that plugins.py and openapi.yaml have the same pathname.
    """

    namespace = "localstack.openapi.spec"

    def __init__(self) -> None:
        # By convention a plugins.py is at the same level (i.e., same pathname) of the openapi.yaml file.
        # importlib.resources would be a better approach but has issues with namespace packages in editable mode
        _module = sys.modules[self.__module__]
        self.spec_path = Path(
            os.path.join(os.path.dirname(os.path.abspath(_module.__file__)), "openapi.yaml")
        )
        assert self.spec_path.exists()
        self.spec = {}

    def load(self):
        with self.spec_path.open("r") as f:
            self.spec = yaml.safe_load(f)


class CoreOASPlugin(OASPlugin):
    name = "localstack"
