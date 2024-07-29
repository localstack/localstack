import re
from typing import AnyStr

from werkzeug.routing import Rule

# Regex to find path parameters in requestUris of AWS service specs (f.e. /{param1}/{param2+})
path_param_regex = re.compile(r"({.+?})")
# Translation table which replaces characters forbidden in Werkzeug rule names with temporary replacements
# Note: The temporary replacements must not occur in any requestUri of any operation in any service!
_rule_replacements = {"-": "_0_"}
# String translation table for #_rule_replacements for str#translate
_rule_replacement_table = str.maketrans(_rule_replacements)


class StrictMethodRule(Rule):
    """
    Small extension to Werkzeug's Rule class which reverts unwanted assumptions made by Werkzeug.
    Reverted assumptions:
    - Werkzeug automatically matches HEAD requests to the corresponding GET request (i.e. Werkzeug's rule automatically
      adds the HEAD HTTP method to a rule which should only match GET requests). This is implemented to simplify
      implementing an app compliant with HTTP (where a HEAD request needs to return the headers of a corresponding GET
      request), but it is unwanted for our strict rule matching in here.
    """

    def __init__(self, string: str, method: str, **kwargs) -> None:
        super().__init__(string=string, methods=[method], **kwargs)

        # Make sure Werkzeug's Rule does not add any other methods
        # (f.e. the HEAD method even though the rule should only match GET)
        self.methods = {method.upper()}


def transform_path_params_to_rule_vars(match: re.Match[AnyStr]) -> str:
    """
    Transforms a request URI path param to a valid Werkzeug Rule string variable placeholder.
    This transformation function should be used in combination with _path_param_regex on the request URIs (without any
    query params).

    :param match: Regex match which contains a single group. The match group is a request URI path param, including the
                    surrounding curly braces.
    :return: Werkzeug rule string variable placeholder which is semantically equal to the given request URI path param

    """
    # get the group match and strip the curly braces
    request_uri_variable: str = match.group(0)[1:-1]

    # if the request URI param is greedy (f.e. /foo/{Bar+}), add Werkzeug's "path" prefix (/foo/{path:Bar})
    greedy_prefix = ""
    if request_uri_variable.endswith("+"):
        greedy_prefix = "path:"
        request_uri_variable = request_uri_variable.strip("+")

    # replace forbidden chars (not allowed in Werkzeug rule variable names) with their placeholder
    escaped_request_uri_variable = request_uri_variable.translate(_rule_replacement_table)

    return f"<{greedy_prefix}{escaped_request_uri_variable}>"


def post_process_arg_name(arg_key: str) -> str:
    """
    Reverses previous manipulations to the path parameters names (like replacing forbidden characters with
    placeholders).
    :param arg_key: Path param key name extracted using Werkzeug rules
    :return: Post-processed ("un-sanitized") path param key
    """
    result = arg_key
    for original, substitution in _rule_replacements.items():
        result = result.replace(substitution, original)
    return result
