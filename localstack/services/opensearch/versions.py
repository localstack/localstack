"""
Functions for querying opensearch versions and getting download URLs. This script is also runnable to generate
the latest install_versions from the github repository tags. Run::

    python -m localstack.services.opensearch.versions

"""
from typing import Dict

import semver

from localstack.aws.api.opensearch import CompatibleVersionsMap
from localstack.utils.common import get_arch

# Internal representation of the versions (without the "OpenSearch_" prefix)
_install_versions = {"1.0": "1.0.0", "1.1": "1.1.0"}
# External representation fo the versions (with the "OpenSearch_" prefix)
install_versions = {
    f"OpenSearch_{key}": f"OpenSearch_{value}" for key, value in _install_versions.items()
}
# List of compatible versions (using the external representations)
compatible_versions = [
    CompatibleVersionsMap(SourceVersion="OpenSearch_1.0", TargetVersions=["OpenSearch_1.1"])
]


def get_install_version(version: str) -> str:
    try:
        if version is not None and version.startswith("OpenSearch_"):
            version = version[len("OpenSearch_") :]
        ver = semver.VersionInfo.parse(version)
        k = f"{ver.major}.{ver.minor}"
    except ValueError:
        ver = version.split(".")
        k = f"{ver[0]}.{ver[1]}"

    if k not in _install_versions:
        raise ValueError("unknown version %s" % version)

    return _install_versions[k]


def get_download_url(version: str) -> str:
    ver_str = str(semver.VersionInfo.parse(get_install_version(version)))
    arch_str = "x64" if get_arch() == "amd64" else "arm64"
    return (
        f"https://artifacts.opensearch.org/releases/bundle/opensearch/"
        f"{ver_str}/opensearch-{ver_str}-linux-{arch_str}.tar.gz"
    )


def fetch_latest_versions() -> Dict[str, str]:  # pragma: no cover
    """
    Fetches from the opensearch git repository tags the latest patch versions for a minor version and returns a
    dictionary where the key corresponds to the minor version, and the value to the patch version. Run this once in a
    while and update the ``install_versions`` constant in this file.

    Example::

        {
            '1.0': '1.0.0',
            '1.1': '1.1.0',
            '1.2': '1.2.2'
        }

    When updating the versions, make sure to not add versions which are currently not yet supported by AWS.

    :returns: a version dictionary
    """
    from collections import defaultdict

    import requests

    versions = []

    i = 0
    while True:
        tags_raw = requests.get(
            f"https://api.github.com/repos/opensearch-project/OpenSearch/tags?per_page=100&page={i}"
        )
        tags = tags_raw.json()
        i += 1
        if not tags:
            break
        versions.extend([tag["name"].lstrip("v") for tag in tags])

    sem_versions = []

    for v in versions:
        try:
            sem_version = semver.VersionInfo.parse(v)
            if not sem_version.prerelease:
                sem_versions.append(sem_version)
        except ValueError:
            pass

    minor = defaultdict(list)

    for ver in sem_versions:
        minor[f"{ver.major}.{ver.minor}"].append(ver)

    return {k: str(max(versions)) for k, versions in minor.items()}


if __name__ == "__main__":  # pragma: no cover
    from pprint import pprint

    pprint(fetch_latest_versions())
