import glob
import logging
import os
import re
import tempfile
import time
from typing import Union

from localstack.constants import MAVEN_REPO_URL
from localstack.utils.archives import untar, unzip
from localstack.utils.files import load_file, mkdir, new_tmp_file, rm_rf, save_file
from localstack.utils.http import download
from localstack.utils.run import run

LOG = logging.getLogger(__name__)

# TODO
# - Migrate the utility functions (migration path?)
#   - If using a migration path, we need to re-introduce the install hook.
# - Ext:
#   - Externalize the ext SSL cert installer to a package installer
#   - Externalize download utils function
#   - Discuss / delete the install_libs.
#     - This could cause problems with tests (they wouldn't download that stuff automatically on startup anymore).
#     - This could cause problems because the services using these packages might expect it to be installed.


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


# -----------------
# HELPER FUNCTIONS
# -----------------


def download_and_extract(archive_url, target_dir, retries=0, sleep=3, tmp_archive=None):
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
            except Exception:
                time.sleep(sleep)
    if ext == ".zip":
        unzip(tmp_archive, target_dir)
    elif ext in [".bz2", ".gz", ".tgz"]:
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
