import json
import os
import time
from typing import Dict, List, Literal, TypedDict

from localstack import config
from localstack.cli import console

StyleType = Literal["default", "success", "warning", "error"]


class Message(TypedDict):
    validAfterTimestampUTC: int
    validBeforeTimestampUTC: int
    priority: int
    presentationStyle: StyleType
    title: str
    body: str


MessageListType = List[Message]

TopicType = Literal["news", "licensing"]
_CacheType = Dict[TopicType, MessageListType]

map_style: Dict[StyleType, str] = {
    "default": "",
    "success": "[green]",
    "warning": "[yellow]",
    "error": "[red]",
}


class UIMessageService:
    def __init__(self, cache_folder: str = os.path.join(config.dirs.cache, "ui_messages")):
        self._cache_folder = cache_folder

        self._cache: _CacheType
        self._cache_path = os.path.join(self._cache_folder, "cache.json")

        self._read_file_cache()

    def _read_file_cache(self):
        try:
            with open(self._cache_path, "r", encoding="utf-8") as file:
                self._cache = json.load(file)
        except FileNotFoundError:
            self._cache = {}

        # todo validate

    def _write_file_cache(self):
        cache_temp_path = os.path.join(self._cache_folder, "cache.json.tmp")

        if not os.path.exists(self._cache_folder):
            os.makedirs(self._cache_folder)

        with open(cache_temp_path, "w") as file:
            json.dump(self._cache, file)

        os.replace(cache_temp_path, self._cache_path)

    def set_messages_for_topic(self, topic: TopicType, messages: MessageListType):
        self._cache[topic] = messages
        self._write_file_cache()

    def get_messages_for_topic(self, topic: TopicType):
        return self._cache[topic]

    def _get_valid_ordered_messages(self) -> MessageListType:
        all_messages: MessageListType = []
        for _, messages in self._cache.items():
            all_messages = all_messages + messages

        now = int(time.time())
        valid_messages = [
            message
            for message in all_messages
            if (
                message["validAfterTimestampUTC"] < now and now < message["validBeforeTimestampUTC"]
            )
        ]
        return sorted(valid_messages, key=lambda x: x["priority"], reverse=True)

    def print_cached_messages(self, show_even_if_empty: bool = False):
        ordered_messages = self._get_valid_ordered_messages()
        cnt_messages = len(ordered_messages)

        if (cnt_messages > 0) or show_even_if_empty:
            console.rule(f"messages ({cnt_messages})")

            for i in range(cnt_messages):
                message = ordered_messages[i]
                console.print(
                    f"({i + 1}/{cnt_messages}) {map_style[message['presentationStyle']]}{message['title']}  - {message['body']}"
                )

            console.rule("EOT")
            print()
