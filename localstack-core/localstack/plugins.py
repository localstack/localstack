import logging
import os
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
    namespace = "localstack.openapi.spec"

    def __init__(self, spec_path: os.PathLike | str) -> None:
        if isinstance(spec_path, str):
            spec_path = Path(spec_path)
        self.spec_path = spec_path
        self.spec = {}

    def load(self):
        with self.spec_path.open("r") as f:
            self.spec = yaml.safe_load(f)
