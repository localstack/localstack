import sys
import time
from typing import Final
import pytest

from localstack.runtime import ui_messages
from localstack.runtime.ui_messages.ui_message_service import UIMessageService, Message

TEST_MESSAGE_LICENSING_A: Final[Message] = Message(priority=100, validAfterTimestampUTC=-1, validBeforeTimestampUTC=sys.maxsize, presentationStyle="default", title="licensing message A title", body="licensing message A body")
TEST_MESSAGE_NEWS_A: Final[Message] = Message(priority=100, validAfterTimestampUTC=-1, validBeforeTimestampUTC=sys.maxsize, presentationStyle="default", title="messageA title", body="news message A body")
TEST_MESSAGE_NEWS_B: Final[Message] = Message(priority=100, validAfterTimestampUTC=-1, validBeforeTimestampUTC=sys.maxsize, presentationStyle="default", title="messageB title", body="news message B body")

def is_message_in_output(message: Message, output: str):
    return message['title'] in output and message['body'] in output

@pytest.fixture
def message_service():
    return ui_messages.get_instance()


class TestUiMessageService:
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

    def test_display_messages_ordered_by_priority(self, message_service: UIMessageService, capsys: pytest.CaptureFixture[str]):
        prio_100 = Message(priority=100, validAfterTimestampUTC=-1, validBeforeTimestampUTC=sys.maxsize, presentationStyle="default", title="-- prio 100 --", body="news message A body")
        prio_200 = Message(priority=200, validAfterTimestampUTC=-1, validBeforeTimestampUTC=sys.maxsize, presentationStyle="default", title="-- prio 200 --", body="news message A body")
        prio_300 = Message(priority=300, validAfterTimestampUTC=-1, validBeforeTimestampUTC=sys.maxsize, presentationStyle="default", title="-- prio 300 --", body="news message A body")

        # add messages in jumbled order
        message_service.set_messages_for_topic("news", [prio_200, prio_100, prio_300])
        message_service.print_cached_messages()

        output: str = capsys.readouterr().out
        position_100 = output.find(prio_100['title'])
        position_200 = output.find(prio_200['title'])
        position_300 = output.find(prio_300['title'])

        assert position_100 > 0
        assert position_200 > 0
        assert position_300 > 0

        assert position_300 < position_200
        assert position_200 < position_100

    def test_omit_message_section_if_no_messages_to_display(self, message_service: UIMessageService, capsys: pytest.CaptureFixture[str]):
        # reset messages by overriding with []
        message_service.set_messages_for_topic("news", [])
        message_service.set_messages_for_topic("licensing", [])

        message_service.print_cached_messages()

        output: str = capsys.readouterr().out
        assert output == ""

    def test_invalid_messages_not_shown(self, message_service: UIMessageService, capsys: pytest.CaptureFixture[str]):
        now = int(time.time())
        not_valid_yet = Message(priority=100, validAfterTimestampUTC=(now + 60), validBeforeTimestampUTC=sys.maxsize, presentationStyle="default", title="title", body="body")
        not_valid_anymore = Message(priority=200, validAfterTimestampUTC=-1, validBeforeTimestampUTC=(now - 60), presentationStyle="default", title="title", body="body")

        message_service.set_messages_for_topic("news", [not_valid_yet, not_valid_anymore])

        message_service.print_cached_messages()
        captured = capsys.readouterr()

        assert not is_message_in_output(not_valid_yet, captured.out)
        assert not is_message_in_output(not_valid_anymore, captured.out)
