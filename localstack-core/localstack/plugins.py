import logging

from localstack import config
from localstack.runtime import hooks
from localstack.utils.files import rm_rf
from localstack.utils.ssl import get_cert_pem_file_path

LOG = logging.getLogger(__name__)


# Register the ArnPartitionRewriteListener only if the feature flag is enabled
@hooks.on_infra_start(should_load=lambda: config.ARN_PARTITION_REWRITING)
def register_partition_adjusting_proxy_listener():
    LOG.info(
        "Registering ArnPartitionRewriteListener to dynamically replace partitions in requests and responses."
    )
    from localstack.aws import handlers
    from localstack.aws.handlers.partition_rewriter import ArnPartitionRewriteHandler

    handlers.preprocess_request.append(ArnPartitionRewriteHandler())


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
