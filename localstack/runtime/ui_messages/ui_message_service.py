import json
import os
from typing import Dict, List, Literal, TypedDict

from localstack import config

from localstack.cli import console

class MessageContent(TypedDict):
    title: str
    body: str

class Message(TypedDict):
    priority: int
    content: MessageContent

MessageListType = List[Message]

TopicType = Literal['news', 'licensing']
_CacheType = Dict[TopicType, MessageListType]


class UIMessageService:

    def __init__(self, cache_folder: str = os.path.join(config.dirs.cache, "ui_messages")):
        self._cache_folder = cache_folder

        self._cache: _CacheType
        self._cache_path = os.path.join(self._cache_folder, "cache.json")

        self._read_file_cache()


    def _read_file_cache(self):
        try:
            with open(self._cache_path, 'r', encoding='utf-8') as file:
                self._cache = json.load(file)
        except FileNotFoundError as _:
            self._cache = {}

        # todo validate


    def _write_file_cache(self):
        cache_temp_path = os.path.join(self._cache_folder, "cache.json.tmp")

        if not os.path.exists(self._cache_folder):
            os.makedirs(self._cache_folder)

        with open(cache_temp_path, 'w') as file:
            json.dump(self._cache, file)

        os.replace(cache_temp_path, self._cache_path)


    def set_messages_for_topic(self, topic: TopicType, messages: MessageListType):
        self._cache[topic] = messages
        self._write_file_cache()


    def _get_ordered_messages(self) -> MessageListType:
        messages_accumulator: MessageListType = []
        for _, messages in self._cache.items():
            messages_accumulator = messages_accumulator + messages

        return sorted(messages_accumulator, key=lambda x: x['priority'], reverse=True)

    def print_cached_messages(self):
        ordered_messages = self._get_ordered_messages()

        if len(ordered_messages) > 0:
            print()
            console.rule("messages")
            for message in ordered_messages:
                print(message['content']['title'] + ' - ' + message['content']['body'])
            console.rule("/messages")
            print()
