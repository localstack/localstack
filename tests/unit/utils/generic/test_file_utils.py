import os

import pytest

from localstack import config
from localstack.testing.pytest.util import run_as_os_user
from localstack.utils.common import new_tmp_file, save_file
from localstack.utils.files import idempotent_chmod, new_tmp_dir, parse_config_file, rm_rf

CONFIG_FILE_SECTION = """
[section{section}]
var1=foo bar 123
var2=123.45
# test comment
var3=Test string' <with% special { chars!

"""


@pytest.mark.parametrize("input_type", ["file", "string"])
@pytest.mark.parametrize("sections", [0, 1, 4])
def test_parse_config_file(input_type, sections):
    config_string = CONFIG_FILE_SECTION.lstrip()

    # generate config string
    if sections == 0:
        config_string = config_string.partition("\n")[2]
    config_string = "\n".join(
        [config_string.replace("{section}", str(i)) for i in range(max(sections, 1))]
    )

    # parse result
    config_input = config_string
    if input_type == "file":
        config_input = new_tmp_file()  # deleted on shutdown
        save_file(config_input, config_string)
    result = parse_config_file(config_input)

    # run assertions
    expected = {
        "var1": "foo bar 123",
        "var2": "123.45",
        "var3": "Test string' <with% special { chars!",
    }
    if sections <= 1:
        assert expected == result
    else:
        assert sections == len(result)
        for section in result.values():
            assert expected == section


@pytest.mark.parametrize("file_type", ["file", "dir"])
@pytest.mark.skipif(
    condition=not config.is_in_docker,
    reason="requires `localstack` user switch, running only in Docker",
)
def test_idempotent_chmod(file_type):
    tmp_file = new_tmp_file() if file_type == "file" else new_tmp_dir()

    # set up initial permissions
    test_mode = 0o765
    os.chmod(tmp_file, test_mode)
    assert os.stat(tmp_file).st_mode & 0o777 == test_mode

    def _test_chmod():
        # assert that regular chmod fails with permission error
        with pytest.raises(PermissionError):
            os.chmod(tmp_file, test_mode)
        # assert that idempotent chmod succeeds
        idempotent_chmod(tmp_file, test_mode)
        # assert that idempotent chmod with different mode fails
        with pytest.raises(PermissionError):
            idempotent_chmod(tmp_file, 0o733)

    # run chmod tests in subprocess (`localstack` user should be available in our Docker container)
    run_as_os_user(_test_chmod, "localstack")

    # clean up
    rm_rf(tmp_file)
