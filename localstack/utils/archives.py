import io
import logging
import os
import tarfile
import zipfile
from subprocess import Popen
from typing import Optional, Union

from .run import is_command_available, run
from .strings import truncate

LOG = logging.getLogger(__name__)


def is_zip_file(content):
    stream = io.BytesIO(content)
    return zipfile.is_zipfile(stream)


def get_unzipped_size(path: str):
    """Returns the size of the unzipped file."""
    with zipfile.ZipFile(path, "r") as zip_ref:
        return sum(f.file_size for f in zip_ref.infolist())


def unzip(path: str, target_dir: str, overwrite: bool = True) -> Optional[Union[str, Popen]]:
    from localstack.utils.platform import is_debian

    use_native_cmd = is_debian() or is_command_available("unzip")
    if use_native_cmd:
        # Running the native command can be an order of magnitude faster in the container. Also, `unzip`
        #  is capable of extracting zip files with incorrect CRC codes (sometimes happens, e.g., with some
        #  Node.js/Serverless versions), which can fail with Python's `zipfile` (extracting empty files).
        flags = ["-o"] if overwrite else []
        flags += ["-q"]
        try:
            cmd = ["unzip"] + flags + [path]
            return run(cmd, cwd=target_dir, print_error=False)
        except Exception as e:
            error_str = truncate(str(e), max_length=200)
            LOG.info(
                'Unable to use native "unzip" command (using fallback mechanism): %s', error_str
            )

    try:
        zip_ref = zipfile.ZipFile(path, "r")
    except Exception as e:
        LOG.warning("Unable to open zip file: %s: %s", path, e)
        raise e

    def _unzip_file_entry(zip_ref, file_entry, target_dir):
        """Extracts a Zipfile entry and preserves permissions"""
        out_path = os.path.join(target_dir, file_entry.filename)
        if use_native_cmd and os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            # this can happen under certain circumstances if the native "unzip" command
            # fails with a non-zero exit code, yet manages to extract parts of the zip file
            return
        zip_ref.extract(file_entry.filename, path=target_dir)
        perm = file_entry.external_attr >> 16
        # Make sure to preserve file permissions in the zip file
        # https://www.burgundywall.com/post/preserving-file-perms-with-python-zipfile-module
        os.chmod(out_path, perm or 0o777)

    try:
        for file_entry in zip_ref.infolist():
            _unzip_file_entry(zip_ref, file_entry, target_dir)
    finally:
        zip_ref.close()


def untar(path: str, target_dir: str):
    mode = "r:gz" if path.endswith("gz") else "r"
    with tarfile.open(path, mode) as tar:
        tar.extractall(path=target_dir)
