import re

from localstack import constants
from localstack.utils.urls import path_from_url


def is_sqs_queue_url(url):
    path = path_from_url(url).partition("?")[0]
    return re.match(r"^/(queue|%s)/[a-zA-Z0-9_-]+(.fifo)?$" % constants.TEST_AWS_ACCOUNT_ID, path)
