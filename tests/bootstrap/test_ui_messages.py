
import time
import pytest
from click.testing import CliRunner
from localstack.cli.localstack import localstack as cli
from tests.fixtures.HTTPMockServer import HTTPMockServer
from localstack import constants, config


@pytest.fixture
def runner():
    return CliRunner()

@pytest.fixture(scope="module")
def news_endpoint_mock():
    with HTTPMockServer(7775, "/news") as response_mock:
        yield response_mock


class TestMessageDisplay:
    def test_show_messages_in_cli(self, runner: CliRunner):

        print(f"test cache folder: '{config.dirs.cache}'")
        # with cached messages file
        # start cli
        result = runner.invoke(cli, ["start", "-d"])
        print("-------------------- output ----------------------")
        print(result.output)
        # assert messages shown before logs, exactly once

    def test_show_messages_in_docker(self):
        # with cached messages file
        # start via docker
        # assert messages shown before other logs, exactly once
        pytest.fail()

    def test_disable_messages_in_cli(self):
        # do not show messages when user disabled them with env var
        pytest.fail()

    def test_disable_messages_in_docker(self):
        # do not show messages when user disabled them with env var
        pytest.fail()


class TestNewsMessages:
    def test_get_news_async(self, runner: CliRunner):
        constants.API_ENDPOINT = "http://localhost:7777"

        # with capsys.disabled():
        runner.invoke(cli, ["start", "-d"])
        runner.invoke(cli, ["wait", "-t", "60"])

        # wait for polling news
        time.sleep(10)

        # stop
        runner.invoke(cli, ["stop"])

        # restart
        result = runner.invoke(cli, ["start", "-d"])

        # assert news are shown
        assert "news" in result.output

    def test_show_messages(self, runner: CliRunner):
        result = runner.invoke(cli, ['messages'])
        print(result.output)
        assert "messages" in result.output



class TestCLI:
    def test_show_messages_command(self):
        # with cached messages file
        # >> localstack messages
        # assert messages
        pytest.fail()

    def test_no_messages_to_display(self):
        # with cached messages file
        # >> localstack messages
        # assert no messages
        pytest.fail()

    def test_poll_news_during_message_command(self):
        # polling news before showing messages
        # then show all the messages
        pytest.fail()


class TestResilience:
    def test_avoid_file_corruption(self):
        pytest.fail()

    def test_recover_from_corrupted_file_cache(self):
        pytest.fail()
