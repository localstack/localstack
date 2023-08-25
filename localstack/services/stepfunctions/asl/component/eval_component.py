import abc
import logging

from localstack.services.stepfunctions.asl.component.component import Component
from localstack.services.stepfunctions.asl.eval.environment import Environment

LOG = logging.getLogger(__name__)


class EvalComponent(Component, abc.ABC):
    def _eval_log(self, subject: str = "Generic") -> str:
        return f"[ASL] [{subject.lower()[:4]}] [{self.__class__.__name__}]: '{self}'."

    def eval(self, env: Environment) -> None:
        if env.is_running():
            LOG.debug(self._eval_log("eval"))
            try:
                self._eval_body(env)
            except Exception as ex:
                LOG.error(f"Exception '{type(ex)}':'{str(ex)}' at '{self._eval_log()}'")
                raise ex
        else:
            LOG.debug(self._eval_log("prun"))

    @abc.abstractmethod
    def _eval_body(self, env: Environment) -> None:
        raise NotImplementedError()
