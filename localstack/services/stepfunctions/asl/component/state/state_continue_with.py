import abc

from localstack.services.stepfunctions.asl.component.common.flow.next import Next


class ContinueWith(abc.ABC):
    ...


class ContinueWithEnd(ContinueWith):
    pass


class ContinueWithNext(ContinueWith):
    def __init__(self, next_state: Next):
        self.next_state: Next = next_state


class ContinueWithSuccess(ContinueWithEnd):
    pass
