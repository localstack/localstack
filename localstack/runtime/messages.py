from typing import Dict, List, Tuple, Literal

import requests

from localstack.cli import console
from localstack.runtime import events
from localstack.utils.threads import start_thread

from localstack.runtime import hooks

class MessageContent:
    title: str
    body: str

class Message:
    priority: int
    content: MessageContent


class Messages:
    MessageListType = List[Message]

    TopicType = Literal['news', 'licensing']
    CacheType = Dict[TopicType, MessageListType]

    # __cache: CacheType = "definitely not a dict..."

    __cache = {
        'news': [{
            'priority': 100,
            'content':
                {
                    'title': 'news title 100',
                    'body': 'some body text'
                }
            },
            {
                'priority': 200,
                'content':
                    {
                        'title': 'news title 200',
                        'body': 'some body text'
                    }
            },
        ],
         'licensing': [{
             'priority': 500,
             'content':
                 {
                     'title': 'licensing title 500',
                     'body': 'your license expired'
                 }
            },
        ]
    }


    @staticmethod
    def set_messages_for_source(source: TopicType, messages: MessageListType):
        Messages.__cache[source] = messages

    @staticmethod
    def __get_ordered_messages() -> MessageListType:

        all_messages: Messages.MessageListType = []
        for topic, messages in Messages.__cache.items():
            all_messages = all_messages + messages

        return sorted(all_messages, key=lambda x: x['priority'], reverse=True)

    @staticmethod
    def print_cached_messages():
        print()
        console.rule("messages")
        for message in Messages.__get_ordered_messages():
            print(message['content']['title'] + ' - ' + message['content']['body'])
        console.rule("/messages")
        print()


def news_thread_func(_):
    print("news thread dispatched")
    events.infra_ready.wait()
    print("infra ready")
    response = requests.post('http://localhost:8080/news', timeout=100)
    print(response.json())
    Messages.set_messages_for_source(source="news", messages=response.json()["messages"])


@hooks.on_infra_ready()
def dispatch_news_client():
    print("dispatching news client...")
    start_thread(news_thread_func, quiet=False)
