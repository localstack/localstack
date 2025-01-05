import abc

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent


class JSONataTemplateValue(EvalComponent, abc.ABC): ...
