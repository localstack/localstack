import os.path
import tempfile
from pathlib import Path

from localstack.utils.archives import create_zip_file_cli, create_zip_file_python


def test_zip_cli():
    with tempfile.TemporaryDirectory() as temp_dir:
        file_name = f"{temp_dir}/test.txt"
        Path(file_name).write_text("example")
        create_zip_file_cli(source_path=temp_dir, base_dir=temp_dir, zip_file="test.zip")
        assert os.path.exists(os.path.join(temp_dir, "test.zip"))


def test_zip_python():
    with tempfile.TemporaryDirectory() as temp_dir:
        full_zip_path = os.path.join(temp_dir, "test.zip")
        file_name = f"{temp_dir}/test.txt"
        Path(file_name).write_text("example")
        create_zip_file_python(base_dir=temp_dir, zip_file=full_zip_path)
        assert os.path.exists(full_zip_path)
