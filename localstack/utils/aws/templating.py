import base64
import json
import re

from six.moves.urllib.parse import quote_plus, unquote_plus

from localstack import config
from localstack.utils.common import extract_jsonpath, recurse_object, short_uid


class VelocityInput(object):
    """Simple class to mimick the behavior of variable '$input' in AWS API Gateway integration velocity templates.
    See: http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html"""

    def __init__(self, value):
        self.value = value

    def path(self, path):
        if not self.value:
            return {}
        value = self.value if isinstance(self.value, dict) else json.loads(self.value)
        return extract_jsonpath(value, path)

    def json(self, path):
        return json.dumps(self.path(path))

    def __getattr__(self, name):
        return self.value.get(name)

    def __repr__(self):
        return "$input"


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
        return str(str(s).replace('"', r"\"")).replace("'", r"\'")


def render_velocity_template(template, context, variables={}, as_json=False):
    import airspeed

    if not template:
        return template

    # Apply a few fixes below, to properly prepare the template...

    # TODO: remove once this PR is merged: https://github.com/purcell/airspeed/pull/48
    def expr_parse(self):
        try:
            self.identity_match(self.DOT)
            self.expression = self.next_element(airspeed.VariableExpression)
        except airspeed.NoMatch:
            self.expression = self.next_element(airspeed.ArrayIndex)
            self.subexpression = None
            try:
                self.subexpression = self.next_element(airspeed.SubExpression)
            except airspeed.NoMatch:
                pass

    airspeed.SubExpression.parse = expr_parse

    # TODO: remove once this PR is merged: https://github.com/purcell/airspeed/pull/48
    def expr_calculate(self, current_object, loader, global_namespace):
        args = [current_object, loader]
        if not isinstance(self.expression, airspeed.ArrayIndex):
            return self.expression.calculate(*(args + [global_namespace]))
        index = self.expression.calculate(*args)
        result = current_object[index]
        if self.subexpression:
            result = self.subexpression.calculate(result, loader, global_namespace)
        return result

    airspeed.SubExpression.calculate = expr_calculate

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
    context_var = {"requestId": short_uid()}
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
