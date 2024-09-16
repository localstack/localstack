import pathlib

import pytest

from localstack.state import AssetDirectory


def test_asset_directory(tmp_path):
    asset_dir = AssetDirectory("sqs", tmp_path)
    assert isinstance(asset_dir.path, pathlib.Path)

    asset_dir_str = AssetDirectory("sqs", str(tmp_path))
    assert isinstance(asset_dir_str.path, pathlib.Path)
    assert asset_dir.path == asset_dir_str.path

    with pytest.raises(ValueError):
        AssetDirectory("sqs", "")

    with pytest.raises(ValueError):
        AssetDirectory("", tmp_path)
