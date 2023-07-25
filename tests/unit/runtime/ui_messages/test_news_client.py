import json
import sys
from typing import Final
import pytest

from localstack.runtime import ui_messages
from localstack.runtime.ui_messages.news_client import dispatch_news_client
from localstack.runtime.ui_messages.ui_message_service import UIMessageService, Message
from localstack.utils.sync import poll_condition
from tests.fixtures.HTTPMockServer import HTTPMockServer, ResponseMock


TEST_MESSAGE_NEWS_A: Final[Message] = Message(priority=100, validAfterTimestampUTC=-1, validBeforeTimestampUTC=sys.maxsize, presentationStyle="default", title="new message A title", body="news message A body")
TEST_MESSAGE_NEWS_B: Final[Message] = Message(priority=100, validAfterTimestampUTC=-1, validBeforeTimestampUTC=sys.maxsize, presentationStyle="default", title="new message B title", body="news message B body")


@pytest.fixture
def message_service():
    return ui_messages.get_instance()


@pytest.fixture(scope="module")
def news_endpoint_mock():
    with HTTPMockServer(port=7778, endpoint="/news") as response_mock:
        yield response_mock


class TestNewsClient:

    def test_fetch_news(self, news_endpoint_mock: ResponseMock):
        news_endpoint_mock.response = '{"messages": [' + json.dumps(TEST_MESSAGE_NEWS_A) + ']}'

        result_handle = dispatch_news_client(news_endpoint_mock.http_endpoint)
        assert poll_condition(lambda: result_handle.has_completed, interval=0.2, timeout=5)
        assert not result_handle.error


    def test_clear_news_on_error(self, news_endpoint_mock: ResponseMock, message_service: UIMessageService):

        message_service.set_messages_for_topic("news", [TEST_MESSAGE_NEWS_A])
        assert message_service.get_messages_for_topic("news") == [TEST_MESSAGE_NEWS_A]

        news_endpoint_mock.response = 'this is not valid json'

        result_handle = dispatch_news_client(news_endpoint_mock.http_endpoint)
        assert poll_condition(lambda: result_handle.has_completed, interval=0.2, timeout=5)
        assert result_handle.error
        assert message_service.get_messages_for_topic("news") == []


    def test_no_exception_if_response_not_json(self, news_endpoint_mock: ResponseMock):
        news_endpoint_mock.set_reponse("this is not valid json")


        result_handle = dispatch_news_client(news_endpoint_mock.http_endpoint)
        assert poll_condition(lambda: result_handle.has_completed, interval=0.2, timeout=5)
        assert result_handle.error

    def test_no_exception_if_response_not_malformed(self, news_endpoint_mock: ResponseMock):
        news_endpoint_mock.set_reponse('{"some-other-property": 42}')


        result_handle = dispatch_news_client(news_endpoint_mock.http_endpoint)
        assert poll_condition(lambda: result_handle.has_completed, interval=0.2, timeout=5)
        assert result_handle.error

