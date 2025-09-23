import re
from typing import Final

from localstack.utils.urls import localstack_host

AWS_URL_SUFFIX = localstack_host().host  # The value in AWS is "amazonaws.com"

PSEUDO_PARAMETERS: Final[set[str]] = {
    "AWS::Partition",
    "AWS::AccountId",
    "AWS::Region",
    "AWS::StackName",
    "AWS::StackId",
    "AWS::URLSuffix",
    "AWS::NoValue",
    "AWS::NotificationARNs",
}

REGEX_OUTPUT_APIGATEWAY = re.compile(
    rf"^(https?://.+\.execute-api\.)(?:[^-]+-){{2,3}}\d\.(amazonaws\.com|{AWS_URL_SUFFIX})/?(.*)$"
)
MOCKED_REFERENCE = "unknown"

VALID_LOGICAL_RESOURCE_ID_RE = re.compile(r"^[A-Za-z0-9]+$")
