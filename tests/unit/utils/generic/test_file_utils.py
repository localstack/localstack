import contextlib
import tempfile

import pytest

from localstack.utils.common import new_tmp_file, save_file
from localstack.utils.files import safe_open
from localstack.utils.generic.file_utils import parse_config_file

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


def test_write_file_atomically():

    # open a temporary file and writes to it, so far nothing new
    tf = tempfile.NamedTemporaryFile()
    with safe_open(tf.name) as f:
        f.write(b"Hello Word")

    # check the content of the file is the expected one
    assert open(tf.name, "r").read() == "Hello Word"

    # open the file again and write to it, but this time, using the standard open call.
    # writes, and even tho we throw an exception, the file will be written.
    with contextlib.suppress(Exception):
        with open(tf.name, "wb+") as f:
            f.write(b"Replace the hello world, ")
            raise Exception("Something went wrong")

    # check the content of the file is not rolled back,
    # and contains the content before the exception
    assert open(tf.name, "r").read() == "Replace the hello world, "

    # let's do the same thing, but this time, using the safe_open call.
    # given an exception is thrown, the content of the file will be rolled back.
    with contextlib.suppress(Exception):
        with safe_open(tf.name) as f:
            f.write(b"This wont be written, ")
            raise Exception("Something went wrong")

    assert open(tf.name, "r").read() == "Replace the hello world, "
