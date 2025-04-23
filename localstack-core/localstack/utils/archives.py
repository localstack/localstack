import glob
import io
import logging
import os
import re
import tarfile
import tempfile
import time
import zipfile
from subprocess import Popen
from typing import IO, Literal, Optional, Union

from localstack.constants import MAVEN_REPO_URL
from localstack.utils.files import load_file, mkdir, new_tmp_file, rm_rf, save_file
from localstack.utils.http import download
from localstack.utils.run import run

from .run import is_command_available
from .strings import truncate

LOG = logging.getLogger(__name__)


StrPath = Union[str, os.PathLike]


def is_zip_file(content):
    stream = io.BytesIO(content)
    return zipfile.is_zipfile(stream)


def get_unzipped_size(zip_file: Union[str, IO[bytes]]):
    """Returns the size of the unzipped file."""
    with zipfile.ZipFile(zip_file, "r") as zip_ref:
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


def create_zip_file_cli(source_path: StrPath, base_dir: StrPath, zip_file: StrPath):
    """
    Creates a zip archive by using the native zip command. The native command can be an order of magnitude faster in CI
    """
    source = "." if source_path == base_dir else os.path.basename(source_path)
    run(["zip", "-r", zip_file, source], cwd=base_dir)


def create_zip_file_python(
    base_dir: StrPath,
    zip_file: StrPath,
    mode: Literal["r", "w", "x", "a"] = "w",
    content_root: Optional[str] = None,
):
    with zipfile.ZipFile(zip_file, mode) as zip_file:
        for root, dirs, files in os.walk(base_dir):
            for name in files:
                full_name = os.path.join(root, name)
                relative = os.path.relpath(root, start=base_dir)
                if content_root:
                    dest = os.path.join(content_root, relative, name)
                else:
                    dest = os.path.join(relative, name)
                zip_file.write(full_name, dest)


def add_file_to_jar(class_file, class_url, target_jar, base_dir=None):
    base_dir = base_dir or os.path.dirname(target_jar)
    patch_class_file = os.path.join(base_dir, class_file)
    if not os.path.exists(patch_class_file):
        download(class_url, patch_class_file)
        run(["zip", target_jar, class_file], cwd=base_dir)


def update_jar_manifest(
    jar_file_name: str, parent_dir: str, search: Union[str, re.Pattern], replace: str
):
    manifest_file_path = "META-INF/MANIFEST.MF"
    jar_path = os.path.join(parent_dir, jar_file_name)
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_manifest_file = os.path.join(tmp_dir, manifest_file_path)
        run(["unzip", "-o", jar_path, manifest_file_path], cwd=tmp_dir)
        manifest = load_file(tmp_manifest_file)

    # return if the search pattern does not match (for idempotence, to avoid file permission issues further below)
    if isinstance(search, re.Pattern):
        if not search.search(manifest):
            return
        manifest = search.sub(replace, manifest, 1)
    else:
        if search not in manifest:
            return
        manifest = manifest.replace(search, replace, 1)

    manifest_file = os.path.join(parent_dir, manifest_file_path)
    save_file(manifest_file, manifest)
    run(["zip", jar_file_name, manifest_file_path], cwd=parent_dir)


def upgrade_jar_file(base_dir: str, file_glob: str, maven_asset: str):
    """
    Upgrade the matching Java JAR file in a local directory with the given Maven asset
    :param base_dir: base directory to search the JAR file to replace in
    :param file_glob: glob pattern for the JAR file to replace
    :param maven_asset: name of Maven asset to download, in the form "<qualified_name>:<version>"
    """

    local_path = os.path.join(base_dir, file_glob)
    parent_dir = os.path.dirname(local_path)
    maven_asset = maven_asset.replace(":", "/")
    parts = maven_asset.split("/")
    maven_asset_url = f"{MAVEN_REPO_URL}/{maven_asset}/{parts[-2]}-{parts[-1]}.jar"
    target_file = os.path.join(parent_dir, os.path.basename(maven_asset_url))
    if os.path.exists(target_file):
        # avoid re-downloading the newer JAR version if it already exists locally
        return
    matches = glob.glob(local_path)
    if not matches:
        return
    for match in matches:
        os.remove(match)
    download(maven_asset_url, target_file)


def download_and_extract(
    archive_url: str,
    target_dir: str,
    retries: Optional[int] = 0,
    sleep: Optional[int] = 3,
    tmp_archive: Optional[str] = None,
) -> None:
    mkdir(target_dir)

    _, ext = os.path.splitext(tmp_archive or archive_url)
    tmp_archive = tmp_archive or new_tmp_file()
    if not os.path.exists(tmp_archive) or os.path.getsize(tmp_archive) <= 0:
        # create temporary placeholder file, to avoid duplicate parallel downloads
        save_file(tmp_archive, "")

        for i in range(retries + 1):
            try:
                download(archive_url, tmp_archive)
                break
            except Exception as e:
                LOG.warning(
                    "Attempt %d. Failed to download archive from %s: %s",
                    i + 1,
                    archive_url,
                    e,
                )
                # only sleep between retries, not after the last one
                if i < retries:
                    time.sleep(sleep)

    # if the temporary file we created above hasn't been replaced, we assume failure
    if os.path.getsize(tmp_archive) <= 0:
        raise Exception("Failed to download archive from %s: . Retries exhausted", archive_url)

    if ext == ".zip":
        unzip(tmp_archive, target_dir)
    elif ext in (
        ".bz2",
        ".gz",
        ".tgz",
        ".xz",
    ):
        untar(tmp_archive, target_dir)
    else:
        raise Exception(f"Unsupported archive format: {ext}")


def download_and_extract_with_retry(archive_url, tmp_archive, target_dir):
    try:
        download_and_extract(archive_url, target_dir, tmp_archive=tmp_archive)
    except Exception as e:
        # try deleting and re-downloading the zip file
        LOG.info("Unable to extract file, re-downloading ZIP archive %s: %s", tmp_archive, e)
        rm_rf(tmp_archive)
        download_and_extract(archive_url, target_dir, tmp_archive=tmp_archive)
