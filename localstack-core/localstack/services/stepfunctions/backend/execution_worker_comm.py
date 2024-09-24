import abc


class ExecutionWorkerCommunication(abc.ABC):
    """
    Defines abstract callbacks for Execution's workers to report their progress, such as termination.
    Execution instances define custom callbacks routines to update their state according to the latest
    relevant state machine evaluation steps.
    """

    @abc.abstractmethod
    def terminated(self) -> None: ...
