import json
from typing import Final
import pytest

from localstack.runtime import ui_messages
from localstack.runtime.ui_messages.news_client import dispatch_news_client
from localstack.runtime.ui_messages.ui_message_service import UIMessageService, Message, MessageContent
from localstack.utils.sync import poll_condition
from tests.fixtures.HTTPMockServer import HTTPMockServer, ResponseMock


TEST_MESSAGE_NEWS_A: Final[Message] = Message(priority=100, content=MessageContent(title="new message A title", body="news message A body"))
TEST_MESSAGE_NEWS_B: Final[Message] = Message(priority=100, content=MessageContent(title="new message B title", body="news message B body"))


@pytest.fixture
def message_service():
    return ui_messages.get_instance()


@pytest.fixture(scope="module")
def news_endpoint_mock():
    with HTTPMockServer(7778, "/news") as response_mock:
        yield response_mock


class CallbackTrigger:
    def __init__(self):
        self.was_callback_triggered: bool = False

    def callback_func(self) -> None:
        self.was_callback_triggered = True

    def was_triggered(self) -> bool:
        return self.was_callback_triggered


class TestNewsClient:

    def test_fetch_news(self, news_endpoint_mock: ResponseMock):
        news_endpoint_mock.response = '{"messages": [' + json.dumps(TEST_MESSAGE_NEWS_A) + ']}'

        trigger = CallbackTrigger()
        dispatch_news_client(news_endpoint_mock.http_endpoint, callback=trigger.callback_func)
        assert poll_condition(trigger.was_triggered, interval=0.2, timeout=5)


    def test_clear_news_on_error(self, news_endpoint_mock: ResponseMock, message_service: UIMessageService):

        message_service.set_messages_for_topic("news", [TEST_MESSAGE_NEWS_A])
        assert message_service.get_messages_for_topic("news") == [TEST_MESSAGE_NEWS_A]

        news_endpoint_mock.response = 'asfdasfdasfd'

        trigger = CallbackTrigger()
        dispatch_news_client(news_endpoint_mock.http_endpoint, callback=trigger.callback_func)
        assert poll_condition(trigger.was_triggered, interval=0.2, timeout=5)
        assert message_service.get_messages_for_topic("news") == []


    def test_no_exception_if_response_not_json(self, news_endpoint_mock: ResponseMock):
        news_endpoint_mock.set_reponse("there's something rotten in the state of Denmark")

        trigger = CallbackTrigger()
        dispatch_news_client(news_endpoint_mock.http_endpoint, callback=trigger.callback_func)
        assert poll_condition(trigger.was_triggered, interval=0.2, timeout=5)

    def test_no_exception_if_response_not_malformed(self, news_endpoint_mock: ResponseMock):
        news_endpoint_mock.set_reponse('{"some-other-property": 42}')

        trigger = CallbackTrigger()
        dispatch_news_client(news_endpoint_mock.http_endpoint, callback=trigger.callback_func)
        assert poll_condition(trigger.was_triggered, interval=0.2, timeout=5)

