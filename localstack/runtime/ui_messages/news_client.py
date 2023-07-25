import logging
from typing import Literal, Optional
from localstack.runtime import ui_messages
from localstack.utils.sync import poll_condition
from localstack.utils.threads import start_thread

from localstack import constants

from localstack.runtime import hooks
import requests
import localstack

LOG = logging.getLogger(__name__)

class NewsResultHandle:
    def __init__(self):
        self.has_completed: bool = False
        self.error: bool = False

def news_thread_func(endpoint: str, result: NewsResultHandle, *args, **kwargs):

    message_service = ui_messages.get_instance()
    ls_version = localstack.__version__
    url = f"{endpoint}/v1/news?localstack-version={ls_version}"

    try:
        response = requests.get(url, timeout=5)
        data = response.json()
        messages = data["messages"] or []
        message_service.set_messages_for_topic(topic="news", messages=messages)

    except Exception as exception: # noqa
        result.error = True
        LOG.warning(f"An error occured while fetching the news from the server: '{exception}")

        message_service.set_messages_for_topic(topic="news", messages=[])

    finally:
        result.has_completed = True


@hooks.on_infra_ready()
def fetch_news_on_infra_ready():
    dispatch_news_client(constants.API_ENDPOINT)

def dispatch_news_client(endpoint: str):
    result_handle =  NewsResultHandle()
    start_thread(lambda _: news_thread_func(endpoint=endpoint, result=result_handle), name="news_client", quiet=False)
    return result_handle

def fetch_news_blocking() -> Literal["success", "error"]:
    result_handle = dispatch_news_client(constants.API_ENDPOINT)
    operation_finished = poll_condition(lambda: result_handle.has_completed, timeout=5)

    if (not operation_finished or result_handle.error):
        if (not operation_finished):
            LOG.warning("Waiting for the news client to fetch news timed out.")

        return "error"

    return "success"
