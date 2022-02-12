import json

from localstack_ext import __version__ as localstack_ext_version

from localstack import __version__ as localstack_version
from localstack import config
from localstack.utils.persistence import (
    STARTUP_INFO_FILE,
    StartupInfo,
    _append_startup_info,
    save_startup_info,
)


class TestStartupInfo:
    def test_append_startup_info_to_new_file(self, tmp_path):
        file_path = tmp_path / "testfile_1.json"

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

    def test_append_startup_info_maintains_order(self, tmp_path):
        file_path = tmp_path / "testfile_2.json"

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

    def test_save_startup_info(self, tmp_path, monkeypatch):
        data_dir = tmp_path / "data"
        monkeypatch.setattr(config.dirs, "data", data_dir)
        config.dirs.mkdirs()

        save_startup_info()

        file_path = data_dir / STARTUP_INFO_FILE

        with file_path.open("r") as fd:
            doc = json.load(fd)

        assert len(doc) == 1
        d = doc[0]

        assert d["timestamp"]
        assert d["localstack_version"] == localstack_version
        assert d["localstack_ext_version"] == localstack_ext_version
        assert d["pro_activated"] in [False, True]
