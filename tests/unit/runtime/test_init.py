import os
import pathlib
import textwrap

import pytest

from localstack.runtime.init import InitScriptManager, Script, Stage, State


@pytest.fixture
def manager(tmp_path) -> InitScriptManager:
    script_root = tmp_path / "etc" / "init"
    script_root.mkdir(parents=True)
    return InitScriptManager(script_root=str(script_root))


class TestInitScriptManager:
    def test_scripts_returns_empty_lists(self, manager):
        # create empty dir to demonstrate it's treated like non-existing
        (pathlib.Path(manager.script_root) / "ready.d").mkdir()

        assert manager.scripts == {
            Stage.BOOT: [],
            Stage.START: [],
            Stage.READY: [],
            Stage.SHUTDOWN: [],
        }

    def test_scripts_returns_scripts_in_alphanumerical_order(self, manager):
        script_root = pathlib.Path(manager.script_root)
        boot_d = script_root / "boot.d"
        start_d = script_root / "start.d"
        ready_d = script_root / "ready.d"
        shutdown_d = script_root / "shutdown.d"

        # noise
        (script_root / "not-a-stage.d").mkdir()

        # create boot scripts
        boot_d.mkdir()
        (boot_d / "01_boot.sh").touch()
        (boot_d / "02_boot.py").touch()
        (boot_d / "03_boot.txt").touch()  # ignored since there is no runner
        (boot_d / "04_boot.sh").touch()
        (boot_d / "notafile").mkdir()

        # create start scripts
        start_d.mkdir()
        (start_d / "01_start.sh").touch()
        (start_d / "03_start.sh").touch()
        (start_d / "03_start.txt").touch()  # ignored since there is no runner
        (start_d / "02_start.py").touch()

        # create ready scripts
        ready_d.mkdir()
        (ready_d / "a_ready.sh").touch()
        (ready_d / "b_ready.py").touch()

        # create ready scripts
        shutdown_d.mkdir()
        (shutdown_d / "shutdown.sh").touch()
        (shutdown_d / "shutdown.py").touch()

        assert manager.scripts == {
            Stage.BOOT: [
                Script(
                    path=os.path.join(manager.script_root, "boot.d/01_boot.sh"),
                    stage=Stage.BOOT,
                    state=State.UNKNOWN,
                ),
                Script(
                    path=os.path.join(manager.script_root, "boot.d/02_boot.py"),
                    stage=Stage.BOOT,
                    state=State.UNKNOWN,
                ),
                Script(
                    path=os.path.join(manager.script_root, "boot.d/04_boot.sh"),
                    stage=Stage.BOOT,
                    state=State.UNKNOWN,
                ),
            ],
            Stage.START: [
                Script(
                    path=os.path.join(manager.script_root, "start.d/01_start.sh"),
                    stage=Stage.START,
                    state=State.UNKNOWN,
                ),
                Script(
                    path=os.path.join(manager.script_root, "start.d/02_start.py"),
                    stage=Stage.START,
                    state=State.UNKNOWN,
                ),
                Script(
                    path=os.path.join(manager.script_root, "start.d/03_start.sh"),
                    stage=Stage.START,
                    state=State.UNKNOWN,
                ),
            ],
            Stage.READY: [
                Script(
                    path=os.path.join(manager.script_root, "ready.d/a_ready.sh"),
                    stage=Stage.READY,
                    state=State.UNKNOWN,
                ),
                Script(
                    path=os.path.join(manager.script_root, "ready.d/b_ready.py"),
                    stage=Stage.READY,
                    state=State.UNKNOWN,
                ),
            ],
            Stage.SHUTDOWN: [
                Script(
                    path=os.path.join(manager.script_root, "shutdown.d/shutdown.py"),
                    stage=Stage.SHUTDOWN,
                    state=State.UNKNOWN,
                ),
                Script(
                    path=os.path.join(manager.script_root, "shutdown.d/shutdown.sh"),
                    stage=Stage.SHUTDOWN,
                    state=State.UNKNOWN,
                ),
            ],
        }

    def test_run_stage_executes_scripts_correctly(self, manager, tmp_path):
        script_root = pathlib.Path(manager.script_root)
        ready_d = script_root / "ready.d"

        ready_d.mkdir()

        script_01 = ready_d / "script_01.sh"
        script_02 = ready_d / "script_02_fails.sh"
        script_03 = ready_d / "script_03.py"

        script_01.touch(mode=0o777)
        script_02.touch(mode=0o777)

        script_01.write_text("#!/bin/bash\necho 'hello 1' >> %s/script_01.out" % tmp_path)
        script_02.write_text("#!/bin/bash\nexit 1")
        script_03.write_text(
            "import pathlib; pathlib.Path('%s').write_text('hello 3')"
            % (tmp_path / "script_03.out")
        )

        assert manager.stage_completed == {
            Stage.BOOT: False,
            Stage.START: False,
            Stage.READY: False,
            Stage.SHUTDOWN: False,
        }
        result = manager.run_stage(Stage.READY)

        # check completed state
        assert manager.stage_completed == {
            Stage.BOOT: False,
            Stage.START: False,
            Stage.READY: True,
            Stage.SHUTDOWN: False,
        }

        # check script results
        assert result == [
            Script(
                path=os.path.join(manager.script_root, "ready.d/script_01.sh"),
                stage=Stage.READY,
                state=State.SUCCESSFUL,
            ),
            Script(
                path=os.path.join(manager.script_root, "ready.d/script_02_fails.sh"),
                stage=Stage.READY,
                state=State.ERROR,
            ),
            Script(
                path=os.path.join(manager.script_root, "ready.d/script_03.py"),
                stage=Stage.READY,
                state=State.SUCCESSFUL,
            ),
        ]

        # check script output
        assert (tmp_path / "script_01.out").read_text().strip() == "hello 1"
        assert (tmp_path / "script_03.out").read_text().strip() == "hello 3"

    def test_python_globals(self, manager, tmp_path):
        """
        https://github.com/localstack/localstack/issues/7135
        """
        script_root = pathlib.Path(manager.script_root)
        ready_d = script_root / "ready.d"
        ready_d.mkdir()

        python_script = ready_d / "script.py"
        python_script.touch(mode=0o777)
        src = textwrap.dedent(
            """
                import os

                TOPICS = ("user-profile", "group")


                def create_topic(topic):
                    os.system(f"echo {topic} creating")


                def init_topics():
                    # access of global variable within scope
                    with open('%s', 'w') as outfile:
                        outfile.write('\\n'.join(TOPICS))

                init_topics()
                """
            % (tmp_path / "script.out")
        )
        python_script.write_text(src)

        assert manager.stage_completed == {
            Stage.BOOT: False,
            Stage.START: False,
            Stage.READY: False,
            Stage.SHUTDOWN: False,
        }
        result = manager.run_stage(Stage.READY)

        # check completed state
        assert manager.stage_completed == {
            Stage.BOOT: False,
            Stage.START: False,
            Stage.READY: True,
            Stage.SHUTDOWN: False,
        }

        # check script results
        assert result == [
            Script(
                path=os.path.join(manager.script_root, "ready.d/script.py"),
                stage=Stage.READY,
                state=State.SUCCESSFUL,
            ),
        ]

        assert (tmp_path / "script.out").read_text().strip() == "user-profile\ngroup"

    def test_empty_init_path(self):
        manager = InitScriptManager(script_root=None)
        scripts = manager.scripts
        assert scripts == {}
