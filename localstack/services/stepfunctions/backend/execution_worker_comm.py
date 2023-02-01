import abc


class ExecutionWorkerComm(abc.ABC):
    @abc.abstractmethod
    def terminated(self) -> None:
        ...
