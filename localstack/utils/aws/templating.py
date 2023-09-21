import contextlib
import json
import re
from typing import Any, Dict

import airspeed

from localstack.utils.objects import recurse_object
from localstack.utils.patch import patch


class VelocityUtil:
    """
    Simple class to mimic the behavior of variable '$util' in AWS velocity templates.

    This class defines basic shared functions, which can be overwritten/extended by
    subclasses (e.g., for API Gateway, AppSync, etc).
    """

    def quiet(self, *args, **kwargs):
        """No-op util function, often used as wrapper around other functions to suppress output"""
        pass

    def qr(self, *args, **kwargs):
        self.quiet(*args, **kwargs)


class VtlTemplate:
    """Utility class for rendering Velocity templates"""

    def render_vtl(self, template: str, variables: Dict, as_json=False) -> str | dict:
        """
        Render the given VTL template against the dict of variables. Note that this is a
        potentially mutating operation which may change the values of `variables` in-place.
        :param template: the template string
        :param variables: dict of variables available to the template
        :param as_json: whether to return the result as parsed JSON dict
        :return: the rendered template string value (or dict)
        """
        if variables is None:
            variables = {}

        if not template:
            return template

        # fix "#set" commands
        template = re.sub(r"(^|\n)#\s+set(.*)", r"\1#set\2", template, re.MULTILINE)

        # enable syntax like "test#${foo.bar}"
        empty_placeholder = " __pLaCe-HoLdEr__ "
        template = re.sub(
            r"([^\s]+)#\$({)?(.*)",
            r"\1#%s$\2\3" % empty_placeholder,
            template,
            re.MULTILINE,
        )

        # add extensions for common string functions below

        class ExtendedString(str):
            def trim(self, *args, **kwargs):
                return ExtendedString(self.strip(*args, **kwargs))

            def toLowerCase(self, *_, **__):
                return ExtendedString(self.lower())

            def toUpperCase(self, *_, **__):
                return ExtendedString(self.upper())

        def apply(obj, **_):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str):
                        obj[k] = ExtendedString(v)
            return obj

        # loop through the variables and enable certain additional util functions (e.g., string utils)
        variables = {} if variables is None else variables
        recurse_object(variables, apply)

        # prepare and render template
        t = airspeed.Template(template)
        namespace = self.prepare_namespace(variables)

        # this steps prepares the namespace for object traversal,
        # e.g, foo.bar.trim().toLowerCase().replace
        input_var = variables.get("input") or {}
        dict_pack = input_var.get("body")
        if isinstance(dict_pack, dict):
            for k, v in dict_pack.items():
                namespace.update({k: v})

        rendered_template = t.merge(namespace)

        # revert temporary changes from the fixes above
        rendered_template = rendered_template.replace(empty_placeholder, "")

        if as_json:
            rendered_template = json.loads(rendered_template)
        return rendered_template

    def prepare_namespace(self, variables: Dict[str, Any]) -> Dict:
        namespace = dict(variables or {})
        namespace.setdefault("context", {})
        if not namespace.get("util"):
            namespace["util"] = VelocityUtil()
        return namespace


# TODO: clean up this function, once all references have been removed (difference between context/variables unclear)
def render_velocity_template(template, context, variables=None, as_json=False):
    context = context or {}
    context.update(variables or {})
    return VtlTemplate().render_vtl(template, context, as_json=as_json)


# START of patches for airspeed
# TODO: contribute these patches upstream!


airspeed.operators.MacroDefinition.RESERVED_NAMES = (
    airspeed.operators.MacroDefinition.RESERVED_NAMES + ("return",)
)


@patch(airspeed.operators.VariableExpression.calculate)
def calculate(fn, self, *args, **kwarg):
    result = fn(self, *args, **kwarg)
    result = "" if result is None else result
    return result


class ExtAssignment(airspeed.operators.Assignment):
    """
    Extends the airspeed Assignment class to support names with dashes, e.g., "X-Amz-Target"
    """

    START = re.compile(r"\s*\(\s*\$(\w*(?:\.[\w-]+|\[\"\$\w+\"\]*)*)\s*=\s*(.*)$", re.S + re.I)


class ExtNameOrCall(airspeed.operators.NameOrCall):
    """
    Extends the airspeed NameOrCall class to support names with dashes, e.g., "foo-bar"
    """

    NAME = re.compile(r"([a-zA-Z0-9_-]+)(.*)$", re.S)


@patch(airspeed.operators.VariableExpression.parse, pass_target=False)
def parse_expr(self):
    self.part = self.next_element(ExtNameOrCall)
    with contextlib.suppress(airspeed.operators.NoMatch):
        self.subexpression = self.next_element(airspeed.operators.SubExpression)


@patch(airspeed.operators.SetDirective.parse, pass_target=False)
def parse_setexpr(self):
    self.identity_match(self.START)
    self.assignment = self.require_next_element(ExtAssignment, "assignment")


class ReturnDirective(airspeed.operators.EvaluateDirective):
    """Defines an airspeed VTL directive that supports `#return(...)` expressions"""

    START = re.compile(r"#return\b(.*)")

    def evaluate_raw(self, stream, namespace, loader):
        import json

        value = self.value.calculate(namespace, loader)
        str_value = str(value)
        # string conversion of certain values (e.g., dict->JSON)
        if isinstance(value, dict):
            try:
                str_value = json.dumps(value)
            except Exception:
                pass
        stream.write(str_value)


@patch(airspeed.operators.Block.parse, pass_target=False)
def parse(self):
    # need to copy the entire function body, no easier way to apply the patch here..
    self.children = []
    while True:
        try:
            self.children.append(
                self.next_element(
                    (
                        airspeed.operators.Text,
                        airspeed.operators.FormalReference,
                        airspeed.operators.Comment,
                        airspeed.operators.IfDirective,
                        airspeed.operators.SetDirective,
                        airspeed.operators.ForeachDirective,
                        airspeed.operators.IncludeDirective,
                        airspeed.operators.ParseDirective,
                        airspeed.operators.MacroDefinition,
                        airspeed.operators.DefineDefinition,
                        airspeed.operators.StopDirective,
                        airspeed.operators.UserDefinedDirective,
                        airspeed.operators.EvaluateDirective,
                        ReturnDirective,
                        airspeed.operators.MacroCall,
                        airspeed.operators.FallthroughHashText,
                    )
                )
            )
        except airspeed.operators.NoMatch:
            break


def dict_to_string(self) -> str:
    return str(self)


def str_contains(self, other: str) -> bool:
    return other in self


airspeed.operators.__additional_methods__[dict]["toString"] = dict_to_string
airspeed.operators.__additional_methods__[str]["contains"] = str_contains

# END of patches for airspeed
