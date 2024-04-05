import logging
import os

from localstack import config
from localstack.services.events.utils import InvalidEventPatternException

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
# TODO: add on-demand jar downloading of selected jars (transitive deps)
JAR_ALL_PATH = os.path.join(THIS_FOLDER, "app-all.jar")

LOG = logging.getLogger(__name__)

if config.EVENT_RULE_ENGINE == "java":
    # TODO: add JPype to pinned dependencies
    import jpype
    import jpype.imports
    from jpype import config as jpype_config
    from jpype import java

    # TODO: double-check whether that's needed
    from jpype.types import *  # noqa: F403

    # Workaround to unblock LocalStack shutdown. By default, JPype wait until all daemon threads are terminated,
    # which blocks the LocalStack shutdown upon any leaked thread (know LS issue).
    # See https://github.com/MPh-py/MPh/issues/15#issuecomment-778486669
    jpype_config.destroy_jvm = False

    if not jpype.isJVMStarted():
        jpype.startJVM(classpath=[JAR_ALL_PATH])

    # Import of the Java class "Ruler" needs to happen after the JVM start
    from software.amazon.event.ruler import Ruler

    def matches_rule(event: str, rule: str) -> bool:
        """Invokes the AWS Event Ruler Java library: https://github.com/aws/event-ruler
        There is a single static boolean method Ruler.matchesRule(event, rule) -
        both arguments are provided as JSON strings.
        """

        try:
            return Ruler.matchesRule(event, rule)
        except java.lang.Exception as e:
            reason = e.args[0]
            raise InvalidEventPatternException(reason=reason)

else:
    # Provide an API-compatible import when using another rule engine to avoid conditional imports
    def matches_rule(event: str, rule: str) -> bool:
        raise NotImplementedError("Set EVENT_RULE_ENGINE=java to enable the Java Event Ruler.")
