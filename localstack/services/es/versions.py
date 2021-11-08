"""
Functions for querying elasticsearch versions and getting download URLs. This script is also runnable to generate
the latest install_versions from the github repository tags. Run::

    python -m localstack.services.es.versions

"""
from typing import Dict

import semver

install_versions = {
    "7.15": "7.15.1",
    "7.14": "7.14.2",
    "7.13": "7.13.4",
    "7.12": "7.12.1",
    "7.11": "7.11.2",
    "7.10": "7.10.0",
    "7.9": "7.9.3",
    "7.8": "7.8.1",
    "7.7": "7.7.1",
    "7.6": "7.6.2",
    "7.5": "7.5.2",
    "7.4": "7.4.2",
    "7.3": "7.3.2",
    "7.2": "7.2.1",
    "7.1": "7.1.1",
    "7.0": "7.0.1",
    "6.8": "6.8.20",
    "6.7": "6.7.2",
    "6.6": "6.6.2",
    "6.5": "6.5.4",
    "6.4": "6.4.3",
    "6.3": "6.3.2",
    "6.2": "6.2.4",
    "6.1": "6.1.4",
    "6.0": "6.0.1",
    "5.6": "5.6.16",
    "5.5": "5.5.3",
    "5.4": "5.4.3",
    "5.3": "5.3.3",
    "5.2": "5.2.2",
    "5.1": "5.1.2",
    "5.0": "5.0.2",
}


def get_install_version(version: str) -> str:
    try:
        ver = semver.VersionInfo.parse(version)
        k = f"{ver.major}.{ver.minor}"
    except ValueError:
        ver = version.split(".")
        k = f"{ver[0]}.{ver[1]}"

    if k not in install_versions:
        raise ValueError("unknown version %s" % version)

    return install_versions[k]


def get_download_url(version: str) -> str:
    ver = semver.VersionInfo.parse(get_install_version(version))
    ver_str = str(ver)

    repo = "https://artifacts.elastic.co/downloads/elasticsearch"

    if ver.major <= 6:
        return f"{repo}/elasticsearch-{ver_str}.tar.gz"

    return f"{repo}/elasticsearch-{ver_str}-linux-x86_64.tar.gz"


def fetch_latest_versions() -> Dict[str, str]:  # pragma: no cover
    """
    Fetches from the elasticsearch git repository tags the latest patch versions for a minor version and returns a
    dictionary where the key corresponds to the minor version, and the value to the patch version. Run this once in a
    while and update the ``install_versions`` constant in this file. Make sure that the DEFAULT_ES_VERSION constants
    however corresponds to the one pre-seeded in the Dockerfile.base.

    Example::

        {
            # ... older version
            '7.7': '7.7.1',
            '7.8': '7.8.1',
            '7.9': '7.9.3',
            '8.0': '8.0.0-alpha2'
        }

    :returns: a version dictionary
    """
    from collections import defaultdict

    import requests

    versions = []

    i = 0
    while True:
        tags = requests.get(
            f"https://api.github.com/repos/elastic/elasticsearch/tags?per_page=100&page={i}"
        ).json()
        i += 1
        if not tags:
            break
        versions.extend([tag["name"].lstrip("v") for tag in tags])

    sem_version = []

    for v in versions:
        try:
            sem_version.append(semver.VersionInfo.parse(v))
        except ValueError:
            pass

    minor = defaultdict(list)

    for ver in sem_version:
        minor[f"{ver.major}.{ver.minor}"].append(ver)

    return {k: str(max(versions)) for k, versions in minor.items()}


if __name__ == "__main__":  # pragma: no cover
    from pprint import pprint

    pprint(fetch_latest_versions())
