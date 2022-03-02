import base64
import json
import re
from urllib.parse import quote_plus, unquote_plus

import airspeed

from localstack import config
from localstack.utils.common import (
    extract_jsonpath,
    is_number,
    json_safe,
    recurse_object,
    short_uid,
)
from localstack.utils.generic.number_utils import to_number
from localstack.utils.patch import patch


# TODO: potentially replace with generic proxy wrapper class
class DictWrapper(dict):
    def keySet(self):
        return self.keys()


class VelocityInput(object):
    """Simple class to mimick the behavior of variable '$input' in AWS API Gateway integration velocity templates.
    See: http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html"""

    def __init__(self, value):
        self.value = self._attach_missing_functions(value)

    def path(self, path):
        if not self.value:
            return {}
        value = self.value if isinstance(self.value, dict) else json.loads(self.value)
        return extract_jsonpath(value, path)

    def json(self, path):
        path = path or "$"
        matching = self.path(path)
        if isinstance(matching, (list, dict)):
            matching = json_safe(matching)
        return json.dumps(matching)

    def __getattr__(self, name):
        return self.value.get(name)

    def __repr__(self):
        return "$input"

    def _attach_missing_functions(self, value):
        if value:

            def _fix(obj, **kwargs):
                if isinstance(obj, dict):
                    return DictWrapper(obj)
                return obj

            value = recurse_object(value, _fix)
        return value


class VelocityUtil(object):
    """Simple class to mimick the behavior of variable '$util' in AWS API Gateway integration velocity templates.
    See: http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html"""

    def base64Encode(self, s):
        if not isinstance(s, str):
            s = json.dumps(s)
        encoded_str = s.encode(config.DEFAULT_ENCODING)
        encoded_b64_str = base64.b64encode(encoded_str)
        return encoded_b64_str.decode(config.DEFAULT_ENCODING)

    def base64Decode(self, s):
        if not isinstance(s, str):
            s = json.dumps(s)
        return base64.b64decode(s)

    def toJson(self, obj):
        return obj and json.dumps(obj)

    def urlEncode(self, s):
        return quote_plus(s)

    def urlDecode(self, s):
        return unquote_plus(s)

    def escapeJavaScript(self, s):
        try:
            return json.dumps(json.loads(s))
        except Exception:
            primitive_types = (str, int, bool, float, type(None))
            s = s if isinstance(s, primitive_types) else str(s)
        if str(s).strip() in ["true", "false"]:
            s = bool(s)
        elif s not in [True, False] and is_number(s):
            s = to_number(s)
        return json.dumps(s)


# TODO: remove code below once this PR is merged/released: https://github.com/purcell/airspeed/pull/56


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


def render_velocity_template(template, context, variables=None, as_json=False):
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

        def toLowerCase(self, *args, **kwargs):
            return ExtendedString(self.lower(*args, **kwargs))

        def toUpperCase(self, *args, **kwargs):
            return ExtendedString(self.upper(*args, **kwargs))

    def apply(obj, **kwargs):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str):
                    obj[k] = ExtendedString(v)
        return obj

    # loop through the variables and enable certain additional util functions (e.g., string utils)
    variables = variables or {}
    recurse_object(variables, apply)

    # prepare and render template
    context_var = variables.get("context") or {}
    context_var.setdefault("requestId", short_uid())
    t = airspeed.Template(template)
    var_map = {
        "input": VelocityInput(context),
        "util": VelocityUtil(),
        "context": context_var,
    }
    var_map.update(variables or {})
    replaced = t.merge(var_map)

    # revert temporary changes from the fixes above
    replaced = replaced.replace(empty_placeholder, "")

    if as_json:
        replaced = json.loads(replaced)
    return replaced
