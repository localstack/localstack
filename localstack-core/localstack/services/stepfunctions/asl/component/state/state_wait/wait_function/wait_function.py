import abc
import logging
import time

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment

LOG = logging.getLogger(__name__)


class WaitFunction(EvalComponent, abc.ABC):
    @abc.abstractmethod
    def _get_wait_seconds(self, env: Environment) -> int: ...

    def _wait_interval(self, env: Environment, wait_seconds: int) -> None:
        t0 = time.time()
        if wait_seconds > 0:
            env.program_state_event.wait(wait_seconds)
        t1 = time.time()
        round_sec_waited = int(t1 - t0)
        wait_seconds_delta = wait_seconds - round_sec_waited
        if wait_seconds_delta <= 0:
            return
        elif env.is_running():
            # Unrelated interrupt: continue waiting.
            LOG.warning(
                "Wait function '%s' successfully reentered waiting for another '%s' seconds.",
                self,
                wait_seconds_delta,
            )
            return self._wait_interval(env=env, wait_seconds=wait_seconds_delta)
        else:
            LOG.info(
                "Wait function '%s' successfully interrupted after '%s' seconds.",
                self,
                round_sec_waited,
            )

    def _eval_body(self, env: Environment) -> None:
        w_sec = self._get_wait_seconds(env=env)
        self._wait_interval(env=env, wait_seconds=w_sec)
