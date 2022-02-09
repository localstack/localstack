import re
from typing import Tuple

from localstack.utils.common import short_uid

RUNTIME_REGEX = r"(?P<runtime>[a-z]+)(?P<version>\d+(\.\d+)?)(?:.*)"

IMAGE_PREFIX = "gallery.ecr.aws/lambda/"


def get_runtime_split(runtime: str) -> Tuple[str, str]:
    match = re.match(RUNTIME_REGEX, runtime)
    runtime, version = match.group("runtime"), match.group("version")
    # sad exception for .net
    if runtime == "dotnetcore":
        runtime = "dotnet"
        version = f"core{version}"
    return runtime, version


class RuntimeExecutor:
    id: str
    function_arn: str

    def __init__(self, function_arn: str, runtime: str):
        self.id = short_uid()
        self.function_arn = function_arn
        self.runtime = runtime

    def get_image(self) -> str:
        # TODO a tad hacky, might cause problems in the future
        runtime, version = get_runtime_split(self.runtime)
        return f"{IMAGE_PREFIX}{runtime}:{version}"

    def start(self):
        env_vars = {"LOCALSTACK_RUNTIME_ID": self.id, "LAMBDA_FUNCTION_ARN": self.function_arn}
        env_vars

    def stop(self):
        pass
