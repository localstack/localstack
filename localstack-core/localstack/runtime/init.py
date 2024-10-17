"""Module for initialization hooks https://docs.localstack.cloud/references/init-hooks/"""

import dataclasses
import logging
import os.path
import subprocess
import time
from enum import Enum
from functools import cached_property
from typing import Dict, List, Optional

from plux import Plugin, PluginManager

from localstack.runtime import hooks
from localstack.utils.objects import singleton_factory

LOG = logging.getLogger(__name__)


class State(Enum):
    UNKNOWN = "UNKNOWN"
    RUNNING = "RUNNING"
    SUCCESSFUL = "SUCCESSFUL"
    ERROR = "ERROR"

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class Stage(Enum):
    BOOT = 0
    START = 1
    READY = 2
    SHUTDOWN = 3

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


@dataclasses.dataclass
class Script:
    path: str
    stage: Stage
    state: State = State.UNKNOWN


class ScriptRunner(Plugin):
    """
    Interface for running scripts.
    """

    namespace = "localstack.init.runner"
    suffixes = []

    def run(self, path: str) -> None:
        """
        Run the given script with the appropriate runtime.

        :param path: the path to the script
        """
        raise NotImplementedError

    def should_run(self, script_file: str) -> bool:
        """
        Checks whether the given file should be run with this script runner. In case multiple runners
        evaluate this condition to true on the same file (ideally this doesn't happen), the first one
        loaded will be used, which is potentially indeterministic.

        :param script_file: the script file to run
        :return: True if this runner should be used, False otherwise
        """
        for suffix in self.suffixes:
            if script_file.endswith(suffix):
                return True
        return False


class ShellScriptRunner(ScriptRunner):
    """
    Runner that interprets scripts as shell scripts and calls them directly.
    """

    name = "sh"
    suffixes = [".sh"]

    def run(self, path: str) -> None:
        exit_code = subprocess.call(args=[], executable=path)
        if exit_code != 0:
            raise OSError("Script %s returned a non-zero exit code %s" % (path, exit_code))


class PythonScriptRunner(ScriptRunner):
    """
    Runner that uses ``exec`` to run a python script.
    """

    name = "py"
    suffixes = [".py"]

    def run(self, path: str) -> None:
        with open(path, "rb") as fd:
            exec(fd.read(), {})


class InitScriptManager:
    _stage_directories: Dict[Stage, str] = {
        Stage.BOOT: "boot.d",
        Stage.START: "start.d",
        Stage.READY: "ready.d",
        Stage.SHUTDOWN: "shutdown.d",
    }

    script_root: str
    stage_completed: Dict[Stage, bool]

    def __init__(self, script_root: str):
        self.script_root = script_root
        self.stage_completed = {stage: False for stage in Stage}
        self.runner_manager: PluginManager[ScriptRunner] = PluginManager(ScriptRunner.namespace)

    @cached_property
    def scripts(self) -> Dict[Stage, List[Script]]:
        return self._find_scripts()

    def get_script_runner(self, script_file: str) -> Optional[ScriptRunner]:
        runners = self.runner_manager.load_all()
        for runner in runners:
            if runner.should_run(script_file):
                return runner
        return None

    def has_script_runner(self, script_file: str) -> bool:
        return self.get_script_runner(script_file) is not None

    def run_stage(self, stage: Stage) -> List[Script]:
        """
        Runs all scripts in the given stage.

        :param stage: the stage to run
        :return: the scripts that were in the stage
        """
        scripts = self.scripts.get(stage, [])

        if self.stage_completed[stage]:
            LOG.debug("Stage %s already completed, skipping", stage)
            return scripts

        try:
            for script in scripts:
                LOG.debug("Running %s script %s", script.stage, script.path)

                env_original = os.environ.copy()

                try:
                    script.state = State.RUNNING
                    runner = self.get_script_runner(script.path)
                    runner.run(script.path)
                except Exception as e:
                    script.state = State.ERROR
                    if LOG.isEnabledFor(logging.DEBUG):
                        LOG.exception("Error while running script %s", script)
                    else:
                        LOG.error("Error while running script %s: %s", script, e)
                else:
                    script.state = State.SUCCESSFUL
                finally:
                    # Discard env variables overridden in startup script that may cause side-effects
                    for env_var in (
                        "AWS_ACCESS_KEY_ID",
                        "AWS_SECRET_ACCESS_KEY",
                        "AWS_SESSION_TOKEN",
                        "AWS_DEFAULT_REGION",
                        "AWS_PROFILE",
                        "AWS_REGION",
                    ):
                        if env_var in env_original:
                            os.environ[env_var] = env_original[env_var]
                        else:
                            os.environ.pop(env_var, None)
        finally:
            self.stage_completed[stage] = True

        return scripts

    def _find_scripts(self) -> Dict[Stage, List[Script]]:
        scripts = {}

        if self.script_root is None:
            LOG.debug("Unable to discover init scripts as script_root is None")
            return {}

        for stage in Stage:
            scripts[stage] = []

            stage_dir = self._stage_directories[stage]
            if not stage_dir:
                continue

            stage_path = os.path.join(self.script_root, stage_dir)
            if not os.path.isdir(stage_path):
                continue

            for root, dirs, files in os.walk(stage_path, topdown=True):
                # from the docs: "When topdown is true, the caller can modify the dirnames list in-place"
                dirs.sort()
                files.sort()
                for file in files:
                    script_path = os.path.abspath(os.path.join(root, file))
                    if not os.path.isfile(script_path):
                        continue

                    # only add the script if there's a runner for it
                    if not self.has_script_runner(script_path):
                        LOG.debug("No runner available for script %s", script_path)
                        continue

                    scripts[stage].append(Script(path=script_path, stage=stage))
        LOG.debug("Init scripts discovered: %s", scripts)

        return scripts


# runtime integration


@singleton_factory
def init_script_manager() -> InitScriptManager:
    from localstack import config

    return InitScriptManager(script_root=config.dirs.init)


@hooks.on_infra_start()
def _run_init_scripts_on_start():
    # this is a hack since we currently cannot know whether boot scripts have been executed or not
    init_script_manager().stage_completed[Stage.BOOT] = True
    _run_and_log(Stage.START)


@hooks.on_infra_ready()
def _run_init_scripts_on_ready():
    _run_and_log(Stage.READY)


@hooks.on_infra_shutdown()
def _run_init_scripts_on_shutdown():
    _run_and_log(Stage.SHUTDOWN)


def _run_and_log(stage: Stage):
    from localstack.utils.analytics import log

    then = time.time()
    scripts = init_script_manager().run_stage(stage)
    took = (time.time() - then) * 1000

    if scripts:
        log.event("run_init", {"stage": stage.name, "scripts": len(scripts), "duration": took})


def main():
    """
    Run the init scripts for a particular stage. For example, to run all boot scripts run::

        python -m localstack.runtime.init BOOT

    The __main__ entrypoint is currently mainly used for the docker-entrypoint.sh. Other stages
    are executed from runtime hooks.
    """
    import sys

    stage = Stage[sys.argv[1]]
    init_script_manager().run_stage(stage)


if __name__ == "__main__":
    main()
