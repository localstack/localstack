import logging
import sys
import warnings

from localstack import config, constants

from .format import AddFormattedAttributes, DefaultFormatter

# The log levels for modules are evaluated incrementally for logging granularity,
# from highest (DEBUG) to lowest (TRACE_INTERNAL). Hence, each module below should have
# higher level which serves as the default.

default_log_levels = {
    "asyncio": logging.INFO,
    "boto3": logging.INFO,
    "botocore": logging.ERROR,
    "docker": logging.WARNING,
    "elasticsearch": logging.ERROR,
    "hpack": logging.ERROR,
    "moto": logging.WARNING,
    "requests": logging.WARNING,
    "s3transfer": logging.INFO,
    "urllib3": logging.WARNING,
    "werkzeug": logging.WARNING,
    "rolo": logging.WARNING,
    "localstack.aws.accounts": logging.INFO,
    "localstack.aws.protocol.serializer": logging.INFO,
    "localstack.aws.serving.wsgi": logging.WARNING,
    "localstack.request": logging.INFO,
    "localstack.request.internal": logging.WARNING,
    "localstack.state.inspect": logging.INFO,
    "localstack_persistence": logging.INFO,
}

trace_log_levels = {
    "rolo": logging.DEBUG,
    "localstack.aws.protocol.serializer": logging.DEBUG,
    "localstack.aws.serving.wsgi": logging.DEBUG,
    "localstack.request": logging.DEBUG,
    "localstack.request.internal": logging.INFO,
    "localstack.state.inspect": logging.DEBUG,
}

trace_internal_log_levels = {
    "localstack.aws.accounts": logging.DEBUG,
    "localstack.request.internal": logging.DEBUG,
}


def setup_logging_for_cli(log_level=logging.INFO):
    logging.basicConfig(level=log_level)

    # set log levels of loggers
    logging.root.setLevel(log_level)
    logging.getLogger("localstack").setLevel(log_level)
    for logger, level in default_log_levels.items():
        logging.getLogger(logger).setLevel(level)


def get_log_level_from_config():
    # overriding the log level if LS_LOG has been set
    if config.LS_LOG:
        log_level = str(config.LS_LOG).upper()
        if log_level.lower() in constants.TRACE_LOG_LEVELS:
            log_level = "DEBUG"
        log_level = logging._nameToLevel[log_level]
        return log_level

    return logging.DEBUG if config.DEBUG else logging.INFO


def setup_logging_from_config():
    log_level = get_log_level_from_config()
    setup_logging(log_level)

    if config.is_trace_logging_enabled():
        for name, level in trace_log_levels.items():
            logging.getLogger(name).setLevel(level)
    if config.LS_LOG == constants.LS_LOG_TRACE_INTERNAL:
        for name, level in trace_internal_log_levels.items():
            logging.getLogger(name).setLevel(level)


def create_default_handler(log_level: int):
    log_handler = logging.StreamHandler(stream=sys.stderr)
    log_handler.setLevel(log_level)
    log_handler.setFormatter(DefaultFormatter())
    log_handler.addFilter(AddFormattedAttributes())
    return log_handler


def setup_logging(log_level=logging.INFO) -> None:
    """
    Configures the python logging environment for LocalStack.

    :param log_level: the optional log level.
    """
    # set create a default handler for the root logger (basically logging.basicConfig but explicit)
    log_handler = create_default_handler(log_level)

    # replace any existing handlers
    logging.basicConfig(level=log_level, handlers=[log_handler])

    # disable some logs and warnings
    warnings.filterwarnings("ignore")
    logging.captureWarnings(True)

    # set log levels of loggers
    logging.root.setLevel(log_level)
    logging.getLogger("localstack").setLevel(log_level)
    for logger, level in default_log_levels.items():
        logging.getLogger(logger).setLevel(level)


def setup_hypercorn_logger(hypercorn_config) -> None:
    """
    Sets the hypercorn loggers, which are created in a peculiar way, to the localstack settings.

    :param hypercorn_config: a hypercorn.Config object
    """
    logger = hypercorn_config.log.access_logger
    if logger:
        logger.handlers[0].addFilter(AddFormattedAttributes())
        logger.handlers[0].setFormatter(DefaultFormatter())

    logger = hypercorn_config.log.error_logger
    if logger:
        logger.handlers[0].addFilter(AddFormattedAttributes())
        logger.handlers[0].setFormatter(DefaultFormatter())
