import logging
import os
from pathlib import Path

from localstack import config
from localstack.packages.functiontrace import functiontrace_package, functiontrace_server_package
from localstack.profiler.upload import upload_profile

LOG = logging.getLogger(__name__)

OUTPUT_DIR = Path(config.dirs.cache) / "profiles"


def start_profiling():
    functiontrace_server_package.install()

    # functiontrace-server must be on the PATH
    os.environ["PATH"] += os.pathsep + functiontrace_server_package.get_installed_dir()

    functiontrace_package.install()

    import _functiontrace
    import functiontrace

    LOG.debug("storing profiles to %s", OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    functiontrace.setup_dependencies()

    LOG.info("Starting profiling")
    _functiontrace.begin_tracing(str(OUTPUT_DIR))


def stop_profiling():
    import _functiontrace

    LOG.info("Stopping profiling")
    _functiontrace.terminate()

    # only enable profile uploading if user opts in
    if not config.ENABLE_PROFILING_REPORT_UPLOAD:
        return

    # determine last profile
    file_candidates = (
        path for path in Path(OUTPUT_DIR).glob("functiontrace*.json*") if "latest" not in str(path)
    )
    profiles = sorted(file_candidates, key=lambda file: file.stat().st_mtime)
    latest_profile = profiles[0]
    url = upload_profile(latest_profile)
    # TODO: add flag to turn off automatic profile uploading
    LOG.info("LocalStack profiling report uploaded and is viewable at: '%s'", url)
