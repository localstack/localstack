import re

import airspeed

from localstack.utils.patch import patch


# TODO: remove code below once this PR is merged/released: https://github.com/purcell/airspeed/pull/56
# TODO: potentially replace with generic proxy wrapper class
class DictWrapper(dict):
    def keySet(self):
        return self.keys()


class DefineDefinition(airspeed.MacroDefinition):
    START = re.compile(r"#define\b(.*)", re.S + re.I)
    NAME = re.compile(r"\s*(\$[a-z][a-z_0-9]*)\b(.*)", re.S + re.I)

    def evaluate_raw(self, stream, namespace, loader):
        global_ns = namespace.top()
        macro_key = self.macro_name.lower()
        macro_key = macro_key.lstrip("$")
        if macro_key in global_ns:
            raise Exception("cannot redefine macro {0}".format(macro_key))

        class ParamWrapper:
            def __init__(self, value):
                self.value = value

            def calculate(self, namespace, loader):
                return self.value

        class ExecuteFunc:
            def __call__(_self, *args, **kwargs):
                args = [ParamWrapper(arg) for arg in args]
                _stream = airspeed.StoppableStream()
                self.execute_macro(_stream, namespace, args, loader)
                return _stream.getvalue()

            def __repr__(self):
                return self.__call__()

        global_ns[macro_key] = ExecuteFunc()


@patch(airspeed.Block.parse, pass_target=False)
def block_parse(self, *args, **kwargs):
    self.children = []
    while True:
        try:
            self.children.append(
                self.next_element(
                    (
                        airspeed.Text,
                        airspeed.FormalReference,
                        airspeed.Comment,
                        airspeed.IfDirective,
                        airspeed.SetDirective,
                        airspeed.ForeachDirective,
                        airspeed.IncludeDirective,
                        airspeed.ParseDirective,
                        airspeed.MacroDefinition,
                        DefineDefinition,
                        airspeed.StopDirective,
                        airspeed.UserDefinedDirective,
                        airspeed.EvaluateDirective,
                        airspeed.MacroCall,
                        airspeed.FallthroughHashText,
                    )
                )
            )
        except airspeed.NoMatch:
            break
