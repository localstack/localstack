import abc


class CatchOutcome(abc.ABC):
    ...


class CatchOutcomeCaught(CatchOutcome):
    pass


class CatchOutcomeNotCaught(CatchOutcome):
    pass
