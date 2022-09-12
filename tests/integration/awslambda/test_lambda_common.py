import logging
import os
import subprocess
import zipfile

from localstack.aws.api.lambda_ import Runtime

LOG = logging.getLogger(__name__)

RUNTIMES_AGGREGATED = {
    "python": [Runtime.python3_7, Runtime.python3_8, Runtime.python3_9],
    "nodejs": [Runtime.nodejs12_x, Runtime.nodejs14_x, Runtime.nodejs16_x],
    "ruby": [Runtime.ruby2_5, Runtime.ruby2_7],
    "java": [Runtime.java8, Runtime.java8_al2, Runtime.java11],
    "dotnet": [
        Runtime.dotnetcore1_0,
        Runtime.dotnetcore2_0,
        Runtime.dotnetcore2_1,
        Runtime.dotnetcore3_1,
        Runtime.dotnet6,
    ],
    "go": [Runtime.go1_x],
    "provided": [Runtime.provided, Runtime.provided_al2],
}


def package_for_lang(scenario: str, runtime: str) -> str:
    """
    :param lang: which language
    :param path: directory to build
    :return: path to built zip file
    """
    scenario_dir = os.path.join(os.path.dirname(__file__), "functions", "common", scenario)
    lang_dir = os.path.join(scenario_dir, runtime)
    build_dir = os.path.join(lang_dir, "build")
    package_path = os.path.join(lang_dir, "handler.zip")

    # caching step
    # TODO: add invalidation (e.g. via storing a hash besides this of all files in src)
    if os.path.exists(package_path) and os.path.isfile(package_path):
        return package_path

    # packaging
    result = subprocess.run(["make", "build"], cwd=os.path.join(lang_dir))
    if result.returncode != 0:
        raise Exception(f"Failed with error code: {result.returncode}")

    # check something is in target now
    target_empty = len(os.listdir(lang_dir)) <= 0

    if target_empty:
        raise Exception("Failed")

    with zipfile.ZipFile(package_path, "w", strict_timestamps=True) as zf:
        for root, dirs, files in os.walk(build_dir):
            rel_dir = os.path.relpath(root, build_dir)
            for f in files:
                zf.write(os.path.join(root, f), arcname=os.path.join(rel_dir, f))

    # make sure package file has been generated
    assert os.path.exists(package_path) and os.path.isfile(package_path)
    return package_path


def generate_create_kwargs(lang: str) -> dict:
    match lang:
        case "python":
            return {"Runtime": "", "Environment": {}}


class TestLambdaRuntimesCommon:
    """
    Directly correlates to the structure found in tests.integration.awslambda.functions.common

    each scenario has the following folder structure

    ./common/<scenario>/runtime/

    runtime can either be directly one of the supported runtimes (e.g. in case of version specific compilation instructions) or one of the keys in RUNTIMES_AGGREGATED

    """

    def test_something_random(self, lambda_client):
        package_for_lang("echo", "python")
