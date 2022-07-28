import re
from typing import Optional

from localstack.utils.aws import aws_stack

# some regexes to use (not used atm)
function_arn_regex = re.compile(
    r"arn:(aws[a-zA-Z-]*)?:lambda:[a-z]{2}(-gov)?-[a-z]+-\d{1}:\d{12}:function:[a-zA-Z0-9-_\.]+(:(\$LATEST|[a-zA-Z0-9-_]+))?"
)
function_name_regex = re.compile(
    r"(arn:(aws[a-zA-Z-]*)?:lambda:)?([a-z]{2}(-gov)?-[a-z]+-\d{1}:)?(\d{12}:)?(function:)?(?P<name>[a-zA-Z0-9-_\.]+)(:(\$LATEST|[a-zA-Z0-9-_]+))?"
)  # also length 1-170 incl.
handler_regex = re.compile(r"[^\s]+")
kms_key_arn_regex = re.compile(r"(arn:(aws[a-zA-Z-]*)?:[a-z0-9-.]+:.*)|()")
role_regex = re.compile(r"arn:(aws[a-zA-Z-]*)?:iam::\d{12}:role/?[a-zA-Z_0-9+=,.@\-_/]+")
master_arn_regex = re.compile(
    r"arn:(aws[a-zA-Z-]*)?:lambda:[a-z]{2}(-gov)?-[a-z]+-\d{1}:\d{12}:function:[a-zA-Z0-9-_]+(:(\$LATEST|[a-zA-Z0-9-_]+))?"
)
signing_job_arn_regex = re.compile(
    r"arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)"
)
signing_profile_version_arn_regex = re.compile(
    r"arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)"
)


def is_qualified_lambda_arn(arn: str):
    return bool(function_arn_regex.match(arn))


def function_name_from_arn(arn: str):
    return function_name_regex.match(arn).group("name")


def qualified_lambda_arn(
    function_name: str, qualifier: Optional[str], account: str, region: str
) -> str:
    partition = aws_stack.get_partition(region)
    qualifier = qualifier or "$LATEST"
    return f"arn:{partition}:lambda:{region}:{account}:function:{function_name}:{qualifier}"
