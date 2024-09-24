import logging

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


def handler(event, context):
    # Logger format: [<log_level>]\tdate\t<request_id>\t<log_message>
    LOGGER.info("RequestId log message")
    return context.aws_request_id
