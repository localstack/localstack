import io
import logging
import os
import tarfile
import zipfile

from .run import run
from .strings import truncate

LOG = logging.getLogger(__name__)


def is_zip_file(content):
    stream = io.BytesIO(content)
    return zipfile.is_zipfile(stream)


def unzip(path, target_dir, overwrite=True):
    from localstack.utils.platform import is_debian

    is_in_debian = is_debian()
    if is_in_debian:
        # Running the native command can be an order of magnitude faster in Alpine on Travis-CI
        flags = "-o" if overwrite else ""
        flags += " -q"
        try:
            return run("cd %s; unzip %s %s" % (target_dir, flags, path), print_error=False)
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
        if is_in_debian and os.path.exists(out_path) and os.path.getsize(out_path) > 0:
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
