from typing import Optional


class Version(str):
    V01 = "0.1"


SUPPORTED_VERSIONS: set[Version] = {Version(Version.V01)}
DEFAULT_VERSION: Version = Version(Version.V01)


class UnsupportedVersion(Exception):
    unsupported_version_str: str
    message: Optional[str]

    def __init__(self, unsupported_version_str: str, message: Optional[str] = None):
        self.unsupported_version_str = unsupported_version_str
        self.message = message

    def __str__(self):
        supported_versions: list[str] = sorted(SUPPORTED_VERSIONS)
        exception_str = (
            f"UnsupportedVersion '{self.unsupported_version_str}', "
            f"supported versions: {supported_versions}."
        )
        if self.message:
            exception_str += f" {self.message}."
        return exception_str


def validate_version_string(version_string: str) -> None:
    if version_string not in SUPPORTED_VERSIONS:
        raise UnsupportedVersion(unsupported_version_str=version_string)
