import json
import unittest

import pytest
from localstack_ext import constants as ext_constants

from localstack import constants
from localstack.utils import persistence
from localstack.utils.persistence import StartupInfo, _append_startup_info, save_startup_info


class TestStartupInfo(unittest.TestCase):
    @pytest.fixture(autouse=True)
    def init_tmpdir(self, tmpdir):
        self.tmpdir = tmpdir

    def test_append_startup_info_to_new_file(self):
        file_path = self.tmpdir.join("testfile_1.json")

        _append_startup_info(
            file_path, StartupInfo("2021-07-07T14:25:36.0", "1.0.0", "0.1.0", False)
        )

        with file_path.open("r") as fd:
            doc = json.load(fd)

        assert len(doc) == 1

        d = doc[0]
        assert d["timestamp"] == "2021-07-07T14:25:36.0"
        assert d["localstack_version"] == "1.0.0"
        assert d["localstack_ext_version"] == "0.1.0"
        assert d["pro_activated"] is False

    def test_append_startup_info_maintains_order(self):
        file_path = self.tmpdir.join("testfile_2.json")

        _append_startup_info(
            file_path, StartupInfo("2021-07-07T14:25:36.0", "1.0.0", "0.1.0", False)
        )
        _append_startup_info(
            file_path, StartupInfo("2021-07-13T11:48:15.1", "1.0.0", "0.1.0", False)
        )

        with file_path.open("r") as fd:
            doc = json.load(fd)

        assert len(doc) == 2

        d = doc[1]
        assert d["timestamp"] == "2021-07-13T11:48:15.1"

    def test_save_startup_info(self):
        old_data_dir = persistence.DATA_DIR
        try:
            persistence.DATA_DIR = self.tmpdir
            save_startup_info()

            file_path = self.tmpdir.join(persistence.STARTUP_INFO_FILE)

            with file_path.open("r") as fd:
                doc = json.load(fd)

            assert len(doc) == 1
            d = doc[0]

            assert d["timestamp"]
            assert d["localstack_version"] == constants.VERSION
            assert d["localstack_ext_version"] == ext_constants.VERSION
            assert d["pro_activated"] in [False, True]

        finally:
            persistence.DATA_DIR = old_data_dir
