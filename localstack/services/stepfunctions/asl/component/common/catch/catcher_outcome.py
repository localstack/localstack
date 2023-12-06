import abc


class CatcherOutcome(abc.ABC):
    ...


class CatcherOutcomeCaught(CatcherOutcome):
    pass


class CatcherOutcomeNotCaught(CatcherOutcome):
    pass
