from localstack.runtime import events
from localstack.runtime import ui_messages
from localstack.utils.threads import start_thread

from localstack import config
from localstack import constants


from localstack.runtime import hooks
import requests


def news_thread_func(_):
    endpoint = constants.API_ENDPOINT
    response = requests.post(f"{endpoint}/news", timeout=100)
    print(response.json())

    message_service = ui_messages.get_instance()
    message_service.set_messages_for_topic(topic="news", messages=response.json()["messages"])


@hooks.on_infra_ready()
def dispatch_news_client():
    print("dispatching news client...")
    start_thread(news_thread_func, quiet=False)
