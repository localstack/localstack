import re
import json
import base64
from six.moves.urllib.parse import quote_plus, unquote_plus
from localstack import config
from localstack.utils.common import recurse_object


class VelocityInput:
    """Simple class to mimick the behavior of variable '$input' in AWS API Gateway integration velocity templates.
    See: http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html"""

    def __init__(self, value):
        self.value = value

    def path(self, path):
        from jsonpath_rw import parse
        value = self.value if isinstance(self.value, dict) else json.loads(self.value)
        jsonpath_expr = parse(path)
        result = [match.value for match in jsonpath_expr.find(value)]
        result = result[0] if len(result) == 1 else result
        return result

    def json(self, path):
        return json.dumps(self.path(path))

    def __repr__(self):
        return '$input'


class VelocityUtil:
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
        return str(s).replace("'", r"\'")


def render_velocity_template(template, context, variables={}, as_json=False):
    import airspeed

    # Apply a few fixes below, to properly prepare the template...

    # fix "#set" commands
    template = re.sub(r'(^|\n)#\s+set(.*)', r'\1#set\2', template, re.MULTILINE)

    # convert "test $foo.bar" into "test ${foo.bar}"
    def replace(match):
        return '%s${%s}' % (match.group(1), match.group(3))
    template = re.sub(r'^(\s*(?!(#[a-zA-Z]+)).*)\$([a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+)', replace, template)

    # enable syntax like "test#${foo.bar}"
    empty_placeholder = ' __pLaCe-HoLdEr__ '
    template = re.sub(r'([^\s]+)#\${(.*)', r'\1#%s${\2' % empty_placeholder, template, re.MULTILINE)

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
    t = airspeed.Template(template)
    var_map = {
        'input': VelocityInput(context),
        'util': VelocityUtil()
    }
    var_map.update(variables or {})
    replaced = t.merge(var_map)

    # revert temporary changes from the fixes above
    replaced = replaced.replace(empty_placeholder, '')

    if as_json:
        replaced = json.loads(replaced)
    return replaced
