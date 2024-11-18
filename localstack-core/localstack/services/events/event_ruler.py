import logging
import os
from functools import cache
from pathlib import Path
from typing import Tuple

from localstack.services.events.models import InvalidEventPatternException
from localstack.services.events.packages import event_ruler_package
from localstack.utils.objects import singleton_factory

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))

LOG = logging.getLogger(__name__)


@singleton_factory
def start_jvm() -> None:
    import jpype
    from jpype import config as jpype_config

    # Workaround to unblock LocalStack shutdown. By default, JPype waits until all daemon threads are terminated,
    # which blocks the LocalStack shutdown during testing because pytest runs LocalStack in a separate thread and
    # `jpype.shutdownJVM()` only works from the main Python thread.
    # Shutting down the JVM: https://jpype.readthedocs.io/en/latest/userguide.html#shutting-down-the-jvm
    # JPype shutdown discussion: https://github.com/MPh-py/MPh/issues/15#issuecomment-778486669
    jpype_config.destroy_jvm = False

    if not jpype.isJVMStarted():
        jvm_lib, event_ruler_libs_path = get_jpype_lib_paths()
        event_ruler_libs_pattern = Path(event_ruler_libs_path).joinpath("*")

        jpype.startJVM(jvm_lib, classpath=[event_ruler_libs_pattern])


@cache
def get_jpype_lib_paths() -> Tuple[str, str]:
    """
    Downloads Event Ruler, its dependencies and returns a tuple of:
    - Path to libjvm.so/libjli.dylib to be used by JPype as jvmpath. JPype requires this to start the JVM.
        See https://jpype.readthedocs.io/en/latest/userguide.html#path-to-the-jvm
    - Path to Event Ruler libraries to be used by JPype as classpath
    """
    installer = event_ruler_package.get_installer()
    installer.install()

    return installer.get_java_lib_path(), installer.get_installed_dir()


def matches_rule(event: str, rule: str) -> bool:
    """Invokes the AWS Event Ruler Java library: https://github.com/aws/event-ruler
    There is a single static boolean method Ruler.matchesRule(event, rule) -
    both arguments are provided as JSON strings.
    """

    start_jvm()
    import jpype.imports  # noqa F401: required for importing Java modules
    from jpype import java

    # Import of the Java class "Ruler" needs to happen after the JVM start
    from software.amazon.event.ruler import Ruler

    try:
        # "Static rule matching" is the easiest implementation to get started.
        # "Matching with a machine" using a compiled machine is faster and enables rule validation before matching.
        # https://github.com/aws/event-ruler?tab=readme-ov-file#matching-with-a-machine
        return Ruler.matchesRule(event, rule)
    except java.lang.Exception as e:
        reason = e.args[0]
        raise InvalidEventPatternException(reason=reason) from e
