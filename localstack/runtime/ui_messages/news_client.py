from localstack.runtime import events
from localstack.runtime.ui_messages import ui_message_service
from localstack.utils.threads import start_thread

from localstack.runtime import hooks
import requests


def news_thread_func(_):
    print("news thread dispatched")
    events.infra_ready.wait()
    print("infra ready")
    response = requests.post('http://localhost:8080/news', timeout=100)
    print(response.json())

    message_service = ui_message_service.get_instance()
    message_service.set_messages_for_topic(topic="news", messages=response.json()["messages"])


@hooks.on_infra_ready()
def dispatch_news_client():
    print("dispatching news client...")
    start_thread(news_thread_func, quiet=False)
