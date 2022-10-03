import datetime
import re
from typing import Optional

# some regexes to use (not used atm)
function_arn_regex = re.compile(
    r"arn:(aws[a-zA-Z-]*)?:lambda:[a-z]{2}(-gov)?-[a-z]+-\d{1}:\d{12}:function:[a-zA-Z0-9-_\.]+:(\$LATEST|[a-zA-Z0-9-_]+)"
)
FUNCTION_NAME_REGEX = re.compile(
    r"(arn:(aws[a-zA-Z-]*)?:lambda:)?((?P<region>[a-z]{2}(-gov)?-[a-z]+-\d{1}):)?(?P<account>\d{12}:)?(function:)?(?P<name>[a-zA-Z0-9-_\.]+)(:(?P<qualifier>\$LATEST|[a-zA-Z0-9-_]+))?"
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
    return FUNCTION_NAME_REGEX.match(arn).group("name")


def unqualified_lambda_arn(function_name: str, account: str, region: str):
    # TODO should get partition here, but current way is too expensive (15-120ms) using aws_stack get_partition
    return f"arn:aws:lambda:{region}:{account}:function:{function_name}"


def qualified_lambda_arn(
    function_name: str, qualifier: Optional[str], account: str, region: str
) -> str:
    qualifier = qualifier or "$LATEST"
    return f"{unqualified_lambda_arn(function_name=function_name, account=account, region=region)}:{qualifier}"


def lambda_arn(function_name: str, qualifier: Optional[str], account: str, region: str) -> str:
    """
    Return the lambda arn for the given parameters, with a qualifier if supplied, without otherwise

    :param function_name: Function name
    :param qualifier: Qualifier. May be left out, then the returning arn does not have one either
    :param account: Account ID
    :param region: Region of the Lambda
    :return: Lambda Arn with or without qualifier
    """
    if qualifier:
        return qualified_lambda_arn(
            function_name=function_name, qualifier=qualifier, account=account, region=region
        )
    else:
        return unqualified_lambda_arn(function_name=function_name, account=account, region=region)


LAMBDA_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f+0000"


def format_lambda_date(date_to_format: datetime.datetime) -> str:
    return date_to_format.strftime(LAMBDA_DATE_FORMAT)


def generate_lambda_date() -> str:
    return format_lambda_date(datetime.datetime.now())
