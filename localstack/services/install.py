# TODO this is just for running the pipeline. remove this before merging.
from localstack.constants import ARTIFACTS_REPO as MOVED_ARTIFACTS_REPO
from localstack.services.stepfunctions.packages import JAR_URLS as MOVED_JAR_URLS
from localstack.utils.archives import add_file_to_jar as moved_add_file_to_jar
from localstack.utils.archives import download_and_extract as moved_download_and_extract
from localstack.utils.archives import (
    download_and_extract_with_retry as moved_download_and_extract_with_retry,
)
from localstack.utils.archives import update_jar_manifest as moved_update_jar_manifest

ARTIFACTS_REPO = MOVED_ARTIFACTS_REPO
JAR_URLS = MOVED_JAR_URLS
add_file_to_jar = moved_add_file_to_jar
update_jar_manifest = moved_update_jar_manifest
download_and_extract_with_retry = moved_download_and_extract_with_retry
download_and_extract = moved_download_and_extract
