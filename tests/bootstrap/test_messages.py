
import time
import pytest
from click.testing import CliRunner
from localstack.cli.localstack import localstack as cli

@pytest.fixture
def runner():
    return CliRunner()

class TestMessages:

    def test_something(self, runner: CliRunner): # pylint: disable=redefined-outer-name
        result = runner.invoke(cli, ["status", "services"])
        assert result.exit_code != 0
        assert "could not connect to LocalStack health endpoint" in result.output

        # runner.invoke(cli, ["start", "-d"])
        # runner.invoke(cli, ["wait", "-t", "60"])

        # result = runner.invoke(cli, ["status", "services"])

        # # just a smoke test
        # assert "dynamodb" in result.output
        # for line in result.output.splitlines():
        #     if "dynamodb" in line:
        #         assert "available" in line

class TestMessageDisplay:
    def test_show_messages_in_cli(self):
        # with cached messages file
        # start cli
        # assert messages shown before logs, exactly once
        pytest.fail

    def test_show_messages_in_docker(self):
        # with cached messages file
        # start via docker
        # assert messages shown before other logs, exactly once
        pytest.fail

    def test_disable_messages_in_cli(self):
        # do not show messages when user disabled them with env var
        pytest.fail

    def test_disable_messages_in_docker(self):
        # do not show messages when user disabled them with env var
        pytest.fail


class TestNewsMessages:
    def test_get_news_async(self):
        # start localstack
        # wait for polling news
        # restart
        # assert news are shown
        pytest.fail

class TestCLI:
    def test_show_messages_command(self):
        # with cached messages file
        # >> localstack messages
        # assert messages
        pytest.fail

    def test_no_messages_to_display(self):
        # with cached messages file
        # >> localstack messages
        # assert messages
        pytest.fail

    def test_poll_news_during_message_command(self):
        # polling news before showing messages
        # then show all the messages
        pytest.fail