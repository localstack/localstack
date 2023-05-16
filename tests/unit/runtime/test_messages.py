from typing import Final
import pytest

from localstack.runtime import ui_messages
from localstack.runtime.ui_messages.ui_message_service import UIMessageService, Message, MessageContent

TEST_MESSAGE_LICENSING_A: Final[Message] = Message(priority=100, content=MessageContent(title="licensing message A title", body="licensing message A body"))
TEST_MESSAGE_NEWS_A: Final[Message] = Message(priority=100, content=MessageContent(title="new message A title", body="news message A body"))
TEST_MESSAGE_NEWS_B: Final[Message] = Message(priority=100, content=MessageContent(title="new message B title", body="news message B body"))

def is_message_in_output(message: Message, output: str):
    return message['content']['title'] in output and message['content']['body'] in output

@pytest.fixture
def message_service():
    return ui_messages.get_instance()

class TestMessages:
    def test_set_messages_for_topic(self, message_service: UIMessageService, capsys: pytest.CaptureFixture[str]):
        message_service.set_messages_for_topic("licensing", [TEST_MESSAGE_LICENSING_A])
        message_service.print_cached_messages()

        captured = capsys.readouterr()
        assert is_message_in_output(TEST_MESSAGE_LICENSING_A, captured.out)

    def test_set_messages_only_affects_topic(self, message_service: UIMessageService, capsys: pytest.CaptureFixture[str]):
        message_service.set_messages_for_topic("licensing", [TEST_MESSAGE_LICENSING_A])
        message_service.set_messages_for_topic("news", [TEST_MESSAGE_NEWS_A])
        message_service.print_cached_messages()

        captured = capsys.readouterr()
        assert is_message_in_output(TEST_MESSAGE_LICENSING_A, captured.out)
        assert is_message_in_output(TEST_MESSAGE_NEWS_A, captured.out)

    def test_set_messages_override_previous_messages(self, message_service: UIMessageService, capsys: pytest.CaptureFixture[str]):
        message_service.set_messages_for_topic("news", [TEST_MESSAGE_NEWS_A])
        message_service.set_messages_for_topic("news", [TEST_MESSAGE_NEWS_B])
        message_service.print_cached_messages()

        captured = capsys.readouterr()

        assert not is_message_in_output(TEST_MESSAGE_NEWS_A, captured.out)
        assert is_message_in_output(TEST_MESSAGE_NEWS_B, captured.out)

    def test_display_messages_by_ordered_by_priority(self, message_service: UIMessageService, capsys: pytest.CaptureFixture[str]):
        prio_100 = Message(priority=100, content=MessageContent(title="-- prio 100 --", body="body"))
        prio_200 = Message(priority=200, content=MessageContent(title="-- prio 200 --", body="body"))
        prio_300 = Message(priority=300, content=MessageContent(title="-- prio 300 --", body="body"))

        # add messages in jumbled order
        message_service.set_messages_for_topic("news", [prio_200, prio_100, prio_300])
        message_service.print_cached_messages()

        output: str = capsys.readouterr().out
        position_100 = output.find(prio_100['content']['title'])
        position_200 = output.find(prio_200['content']['title'])
        position_300 = output.find(prio_300['content']['title'])

        assert position_100 > 0
        assert position_200 > 0
        assert position_300 > 0

        assert position_300 < position_200
        assert position_200 < position_100

    def test_no_output_if_no_messages(self, message_service: UIMessageService, capsys: pytest.CaptureFixture[str]):
        # reset messages by overriding with []
        message_service.set_messages_for_topic("news", [])
        message_service.set_messages_for_topic("licensing", [])

        message_service.print_cached_messages()

        output: str = capsys.readouterr().out
        assert output == ""

class TestNewsClient:
    def test_fetch_news(self):
        pytest.fail()