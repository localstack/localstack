from abc import ABC

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent


class Comparison(EvalComponent, ABC):
    ...
