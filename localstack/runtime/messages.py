import json
import os
from typing import Any, Dict, List, Tuple, Literal, TypedDict

import requests
from localstack import config

from localstack.cli import console
from localstack.runtime import events
from localstack.utils.threads import start_thread

from localstack.runtime import hooks

class MessageContent(TypedDict):
    title: str
    body: str

class Message(TypedDict):
    priority: int
    content: MessageContent

CACHE_FOLDER = os.path.join(config.dirs.cache, "messages")
CACHE_PATH = os.path.join(CACHE_FOLDER, "cache.json")
CACHE_TEMP_PATH = os.path.join(CACHE_FOLDER, "cache.json.tmp")


class Messages:
    MessageListType = List[Message]

    TopicType = Literal['news', 'licensing']
    CacheType = Dict[TopicType, MessageListType]

    _cache: CacheType = {}

    @staticmethod
    def _read_file_cache():
        try:
            with open(CACHE_PATH, 'r') as file:
                Messages._cache = json.load(file)
        except FileNotFoundError as _:
            Messages._cache = {}

        # todo validate


    @staticmethod
    def _write_file_cache():
        temp_name = 'messages.tmp'

        if not os.path.exists(CACHE_FOLDER):
            os.makedirs(CACHE_FOLDER)

        with open(CACHE_TEMP_PATH, 'w') as file:
            json.dump(Messages._cache, file)

        os.replace(CACHE_TEMP_PATH, CACHE_PATH)


    @staticmethod
    def set_messages_for_topic(topic: TopicType, messages: MessageListType):
        Messages._read_file_cache()
        Messages._cache[topic] = messages
        Messages._write_file_cache()


    @staticmethod
    def _get_ordered_messages() -> MessageListType:
        Messages._read_file_cache()

        all_messages: Messages.MessageListType = []
        for _, messages in Messages._cache.items():
            all_messages = all_messages + messages

        return sorted(all_messages, key=lambda x: x['priority'], reverse=True)

    @staticmethod
    def print_cached_messages():
        print()
        console.rule("messages")
        for message in Messages._get_ordered_messages():
            print(message['content']['title'] + ' - ' + message['content']['body'])
        console.rule("/messages")
        print()


def news_thread_func(_):
    print("news thread dispatched")
    events.infra_ready.wait()
    print("infra ready")
    response = requests.post('http://localhost:8080/news', timeout=100)
    print(response.json())
    Messages.set_messages_for_topic(topic="news", messages=response.json()["messages"])


@hooks.on_infra_ready()
def dispatch_news_client():
    print("dispatching news client...")
    start_thread(news_thread_func, quiet=False)


