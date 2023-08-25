import abc
import datetime
import logging

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment

LOG = logging.getLogger(__name__)


class WaitFunction(EvalComponent, abc.ABC):
    @abc.abstractmethod
    def _get_wait_seconds(self, env: Environment) -> int:
        ...

    def _wait_interval(self, env: Environment, seconds_waited: int, max_seconds: int) -> None:
        t0 = datetime.datetime.now().second
        if seconds_waited < max_seconds:
            env.program_state_event.wait(max_seconds - seconds_waited)
        t1 = datetime.datetime.now().second
        round_sec_waited = t1 - t0
        tot_sec_waited = seconds_waited + round_sec_waited
        if tot_sec_waited >= max_seconds:
            return
        elif env.is_running():
            # Unrelated interrupt: continue waiting.
            LOG.warning(
                f"Wait function '{self}' successfully reentered waiting for "
                f"another '{max_seconds - tot_sec_waited}' seconds."
            )
            return self._wait_interval(
                env=env, seconds_waited=tot_sec_waited, max_seconds=max_seconds
            )
        else:
            LOG.info(
                f"Wait function '{self}' successfully interrupted after '{tot_sec_waited}' seconds."
            )

    def _eval_body(self, env: Environment) -> None:
        w_sec = self._get_wait_seconds(env=env)
        self._wait_interval(env=env, seconds_waited=0, max_seconds=w_sec)
