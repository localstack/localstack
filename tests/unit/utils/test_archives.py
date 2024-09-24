import os.path

from localstack.utils.archives import create_zip_file_cli, create_zip_file_python


def test_zip_cli(tmp_path):
    file = tmp_path / "test.txt"
    file.write_text("example")
    create_zip_file_cli(source_path=tmp_path, base_dir=tmp_path, zip_file="test.zip")
    assert os.path.exists(os.path.join(tmp_path, "test.zip"))


def test_zip_python(tmp_path):
    full_zip_path = tmp_path / "test.zip"
    file = tmp_path / "test.txt"
    file.write_text("example")
    create_zip_file_python(base_dir=tmp_path, zip_file=full_zip_path)
    assert os.path.exists(full_zip_path)
