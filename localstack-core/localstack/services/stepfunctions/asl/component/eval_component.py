import abc
import logging
from typing import Optional

from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.component import Component
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.utils.strings import long_uid

LOG = logging.getLogger(__name__)


class EvalComponent(Component, abc.ABC):
    __heap_key: Optional[str] = None

    @property
    def heap_key(self) -> str:
        if self.__heap_key is None:
            self.__heap_key = long_uid()
        return self.__heap_key

    def _log_evaluation_step(self, subject: str = "Generic") -> None:
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "[ASL] [%s] [%s]: '%s'",
                subject.lower()[:4],
                self.__class__.__name__,
                repr(self),
            )

    def _log_failure_event_exception(self, failure_event_exception: FailureEventException) -> None:
        error_log_parts = ["Exception=FailureEventException"]

        error_name = failure_event_exception.failure_event.error_name
        if error_name:
            error_log_parts.append(f"Error={error_name.error_name}")

        event_details = failure_event_exception.failure_event.event_details
        if event_details:
            error_log_parts.append(f"Details={to_json_str(event_details)}")

        error_log = ", ".join(error_log_parts)
        component_repr = repr(self)
        LOG.error("%s at '%s'", error_log, component_repr)

    def _log_exception(self, exception: Exception) -> None:
        exception_name = exception.__class__.__name__

        error_log_parts = [f"Exception={exception_name}"]

        exception_body = list(exception.args)
        if exception_body:
            error_log_parts.append(f"Details={exception_body}")
        else:
            error_log_parts.append("Details=None-Available")

        error_log = ", ".join(error_log_parts)
        component_repr = repr(self)
        LOG.error("%s at '%s'", error_log, component_repr)

    def eval(self, env: Environment) -> None:
        if env.is_running():
            self._log_evaluation_step("Computing")
            try:
                self._eval_body(env)
            except FailureEventException as failure_event_exception:
                self._log_failure_event_exception(failure_event_exception=failure_event_exception)
                raise failure_event_exception
            except Exception as exception:
                self._log_exception(exception=exception)
                raise exception
        else:
            self._log_evaluation_step("Pruning")

    @abc.abstractmethod
    def _eval_body(self, env: Environment) -> None:
        raise NotImplementedError()
