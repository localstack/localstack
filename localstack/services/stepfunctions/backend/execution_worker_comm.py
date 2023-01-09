import abc
from typing import Optional

from localstack.aws.api.stepfunctions import SensitiveData


# TODO: add controls.
class ExecutionWorkerComm(abc.ABC):
    @abc.abstractmethod
    def succeed(self, result_data: Optional[SensitiveData]):
        ...
