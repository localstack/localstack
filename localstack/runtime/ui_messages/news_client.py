from typing import Callable, Optional
from localstack.runtime import ui_messages
from localstack.utils.threads import start_thread

from localstack import config
from localstack import constants

from localstack.runtime import hooks
import requests

import json


def news_thread_func(endpoint: str, callback: Optional[Callable[[], None]] = None, *args, **kwargs):

    message_service = ui_messages.get_instance()

    try:
        response = requests.post(f"{endpoint}/news", timeout=100)
        data = json.loads(response.json())
        messages = data["messages"] or []
        message_service.set_messages_for_topic(topic="news", messages=messages)
    except:
        # todo error handling
        print("something failed")
        message_service.set_messages_for_topic(topic="news", messages=[])

    finally:
        if callback:
            callback()


@hooks.on_infra_ready()
def fetch_news_on_infra_ready():
    dispatch_news_client(constants.API_ENDPOINT)


def dispatch_news_client(endpoint: str, callback: Optional[Callable[[], None]] = None):
    print("dispatching news client...")
    start_thread(lambda _: news_thread_func(endpoint=endpoint, callback=callback), name="news_client", quiet=False)