"""
Functions for querying opensearch versions and getting download URLs. This script is also runnable to generate
the latest install_versions from the github repository tags. Run::

    python -m localstack.services.opensearch.versions

"""
from typing import Dict

import semver

from localstack.aws.api.opensearch import CompatibleVersionsMap, EngineType
from localstack.utils.common import get_arch

# Internal representation of the OpenSearch versions (without the "OpenSearch_" prefix)
_opensearch_install_versions = {
    "1.0": "1.0.0",
    "1.1": "1.1.0",
    "1.2": "1.2.4",
    "1.3": "1.3.9",
    "2.3": "2.3.0",
    "2.5": "2.5.0",
}
# Internal representation of the Elasticsearch versions (without the "Elasticsearch_" prefix)
_elasticsearch_install_versions = {
    "7.10": "7.10.0",
    "7.9": "7.9.3",
    "7.8": "7.8.1",
    "7.7": "7.7.1",
    "7.4": "7.4.2",
    "7.1": "7.1.1",
    "6.8": "6.8.20",
    "6.7": "6.7.2",
    "6.5": "6.5.4",
    "6.4": "6.4.3",
    "6.3": "6.3.2",
    "6.2": "6.2.4",
    "6.0": "6.0.1",
    "5.6": "5.6.16",
    "5.5": "5.5.3",
    "5.3": "5.3.3",
    "5.1": "5.1.2",
}
#  prefixed versions
_prefixed_opensearch_install_versions = {
    f"OpenSearch_{key}": value for key, value in _opensearch_install_versions.items()
}
_prefixed_elasticsearch_install_versions = {
    f"Elasticsearch_{key}": value for key, value in _elasticsearch_install_versions.items()
}
install_versions = {
    **_prefixed_opensearch_install_versions,
    **_prefixed_elasticsearch_install_versions,
}

# List of compatible versions (using the external representations)
compatible_versions = [
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_5.1",
        TargetVersions=["Elasticsearch_5.6"],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_5.3",
        TargetVersions=["Elasticsearch_5.6"],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_5.5",
        TargetVersions=["Elasticsearch_5.6"],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_5.6",
        TargetVersions=[
            "Elasticsearch_6.3",
            "Elasticsearch_6.4",
            "Elasticsearch_6.5",
            "Elasticsearch_6.7",
            "Elasticsearch_6.8",
        ],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_6.0",
        TargetVersions=[
            "Elasticsearch_6.3",
            "Elasticsearch_6.4",
            "Elasticsearch_6.5",
            "Elasticsearch_6.7",
            "Elasticsearch_6.8",
        ],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_6.2",
        TargetVersions=[
            "Elasticsearch_6.3",
            "Elasticsearch_6.4",
            "Elasticsearch_6.5",
            "Elasticsearch_6.7",
            "Elasticsearch_6.8",
        ],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_6.3",
        TargetVersions=[
            "Elasticsearch_6.4",
            "Elasticsearch_6.5",
            "Elasticsearch_6.7",
            "Elasticsearch_6.8",
        ],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_6.4",
        TargetVersions=["Elasticsearch_6.5", "Elasticsearch_6.7", "Elasticsearch_6.8"],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_6.5",
        TargetVersions=["Elasticsearch_6.7", "Elasticsearch_6.8"],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_6.7",
        TargetVersions=["Elasticsearch_6.8"],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_6.8",
        TargetVersions=[
            "Elasticsearch_7.1",
            "Elasticsearch_7.4",
            "Elasticsearch_7.7",
            "Elasticsearch_7.8",
            "Elasticsearch_7.9",
            "Elasticsearch_7.10",
            "OpenSearch_1.0",
            "OpenSearch_1.1",
            "OpenSearch_1.2",
            "OpenSearch_1.3",
        ],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_7.1",
        TargetVersions=[
            "Elasticsearch_7.4",
            "Elasticsearch_7.7",
            "Elasticsearch_7.8",
            "Elasticsearch_7.9",
            "Elasticsearch_7.10",
            "OpenSearch_1.0",
            "OpenSearch_1.1",
            "OpenSearch_1.2",
            "OpenSearch_1.3",
        ],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_7.4",
        TargetVersions=[
            "Elasticsearch_7.7",
            "Elasticsearch_7.8",
            "Elasticsearch_7.9",
            "Elasticsearch_7.10",
            "OpenSearch_1.0",
            "OpenSearch_1.1",
            "OpenSearch_1.2",
            "OpenSearch_1.3",
        ],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_7.7",
        TargetVersions=[
            "Elasticsearch_7.8",
            "Elasticsearch_7.9",
            "Elasticsearch_7.10",
            "OpenSearch_1.0",
            "OpenSearch_1.1",
            "OpenSearch_1.2",
            "OpenSearch_1.3",
        ],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_7.8",
        TargetVersions=[
            "Elasticsearch_7.9",
            "Elasticsearch_7.10",
            "OpenSearch_1.0",
            "OpenSearch_1.1",
            "OpenSearch_1.2",
            "OpenSearch_1.3",
        ],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_7.9",
        TargetVersions=[
            "Elasticsearch_7.10",
            "OpenSearch_1.0",
            "OpenSearch_1.1",
            "OpenSearch_1.2",
            "OpenSearch_1.3",
        ],
    ),
    CompatibleVersionsMap(
        SourceVersion="Elasticsearch_7.10",
        TargetVersions=["OpenSearch_1.0", "OpenSearch_1.1", "OpenSearch_1.2", "OpenSearch_1.3"],
    ),
    CompatibleVersionsMap(
        SourceVersion="OpenSearch_1.0",
        TargetVersions=["OpenSearch_1.1", "OpenSearch_1.2", "OpenSearch_1.3"],
    ),
    CompatibleVersionsMap(
        SourceVersion="OpenSearch_1.1",
        TargetVersions=["OpenSearch_1.2", "OpenSearch_1.3"],
    ),
    CompatibleVersionsMap(
        SourceVersion="OpenSearch_1.2",
        TargetVersions=["OpenSearch_1.3"],
    ),
    CompatibleVersionsMap(
        SourceVersion="OpenSearch_1.3",
        TargetVersions=["OpenSearch_2.3", "OpenSearch_2.5"],
    ),
    CompatibleVersionsMap(
        SourceVersion="OpenSearch_2.3",
        TargetVersions=["OpenSearch_2.5"],
    ),
]


def get_install_type_and_version(version: str) -> (EngineType, str):
    engine_type = EngineType(version.split("_")[0])

    if version not in install_versions:
        raise ValueError(f"unknown version {version}")

    return engine_type, install_versions[version]


def get_engine_type(version: str) -> EngineType:
    return EngineType(version.split("_")[0])


def get_install_version(version: str) -> str:
    if version not in install_versions:
        raise ValueError(f"unknown version {version}")

    return install_versions[version]


def _opensearch_url(install_version: semver.VersionInfo) -> str:
    arch = "x64" if get_arch() == "amd64" else "arm64"
    version = str(install_version)
    return (
        f"https://artifacts.opensearch.org/releases/bundle/opensearch/"
        f"{version}/opensearch-{version}-linux-{arch}.tar.gz"
    )


def _es_url(install_version: semver.VersionInfo) -> str:
    arch = "x86_64" if get_arch() == "amd64" else "aarch64"
    version = str(install_version)
    repo = "https://artifacts.elastic.co/downloads/elasticsearch"
    if install_version.major <= 6:
        return f"{repo}/elasticsearch-{version}.tar.gz"

    return f"{repo}/elasticsearch-{version}-linux-{arch}.tar.gz"


def get_download_url(install_version: str, engine_type: EngineType) -> str:
    install_version = semver.VersionInfo.parse(install_version)
    if engine_type == EngineType.OpenSearch:
        return _opensearch_url(install_version)
    elif engine_type == EngineType.Elasticsearch:
        return _es_url(install_version)


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
