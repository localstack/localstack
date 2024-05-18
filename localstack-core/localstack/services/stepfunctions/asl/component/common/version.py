from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component


class Version(Component):
    _SUPPORTED_VERSIONS: Final[set[str]] = {"1.0"}

    version: Final[str]

    def __init__(self, version: str):
        if version not in self._SUPPORTED_VERSIONS:
            raise ValueError(
                f"Version value '{version}' is not accepted. Supported Versions: {list(self._SUPPORTED_VERSIONS)}"
            )

        self.version = version
