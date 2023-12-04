import abc
from typing import Final

from jsonpath_ng import parse

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class MaxItemsDecl(EvalComponent, abc.ABC):
    @abc.abstractmethod
    def _get_value(self, env: Environment) -> int:
        ...

    def _eval_body(self, env: Environment) -> None:
        max_items: int = self._get_value(env=env)
        env.stack.append(max_items)


class MaxItems(MaxItemsDecl):
    """
    "MaxItems": Limits the number of data items passed to the Map state. For example, suppose that you provide a
    CSV file that contains 1000 rows and specify a limit of 100. Then, the interpreter passes only 100 rows to the
    Map state. The Map state processes items in sequential order, starting after the header row.
    Currently, you can specify a limit of up to 100,000,000
    """

    MAX_VALUE: Final[int] = 100_000_000

    max_items: Final[int]

    def __init__(self, max_items: int = MAX_VALUE):
        if max_items < 0 or max_items > MaxItems.MAX_VALUE:
            raise ValueError(
                f"MaxItems value MUST be a non-negative integer "
                f"non greater than '{MaxItems.MAX_VALUE}', got '{max_items}'."
            )
        self.max_items = max_items

    def _get_value(self, env: Environment) -> int:
        return self.max_items


class MaxItemsPath(MaxItemsDecl):
    """
    "MaxItemsPath": computes a MaxItems value equal to the reference path it points to.
    """

    def __init__(self, path: str):
        self.path: Final[str] = path

    def _get_value(self, env: Environment) -> int:
        input_expr = parse(self.path)
        max_items = input_expr.find(env.inp)
        return max_items
