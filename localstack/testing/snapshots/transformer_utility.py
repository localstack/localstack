import re
from datetime import datetime
from typing import Callable, Optional, Pattern

from localstack.testing.snapshots.transformer import (
    GenericTransformer,
    JsonpathTransformer,
    KeyValueBasedTransformer,
    RegexTransformer,
    ResponseMetaDataTransformer,
    Transformer,
)

PATTERN_UUID = re.compile(
    r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"
)
PATTERN_ISO8601 = re.compile(
    r"(?:[1-9]\d{3}-(?:(?:0[1-9]|1[0-2])-(?:0[1-9]|1\d|2[0-8])|(?:0[13-9]|1[0-2])-(?:29|30)|(?:0[13578]|1[02])-31)|(?:[1-9]\d(?:0[48]|[2468][048]|[13579][26])|(?:[2468][048]|[13579][26])00)-02-29)T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-][01]\d:?([0-5]\d)?)"
)
PATTERN_ARN = re.compile(
    r"arn:(aws[a-zA-Z-]*)?:([a-zA-Z0-9-_.]+)?:[a-z]{2}(-gov)?(-[a-z]+-\d{1})?:(\d{12})?((:[^:\\\"]+)+)"
)


# TODO currently unused
# PATTERN_S3_URL = re.compile(
#     r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}(\+[0-9]{4})?"
# )
# PATTERN_SQS_URL = re.compile(
#     r"https?://[^/]+/\d{12}/[^/\"]+"
# )  # TODO: differences here between AWS + localstack structure
#
# PATTERN_HASH_256 = re.compile(r"^[A-Fa-f0-9]{64}$")


class TransformerUtility:
    @staticmethod
    def key_value(
        key: str, value_replacement: Optional[str] = None, reference_replacement: bool = True
    ):
        return KeyValueBasedTransformer(
            lambda k, v: v if k == key else None,
            replacement=value_replacement or _replace_camel_string_with_hyphen(key),
            replace_reference=reference_replacement,
        )

    @staticmethod
    def jsonpath(jsonpath: str, value_replacement: str, reference_replacement: bool = True):
        return JsonpathTransformer(
            jsonpath=jsonpath,
            replacement=value_replacement,
            replace_reference=reference_replacement,
        )

    @staticmethod
    def custom(fn: Callable[[dict], dict]) -> Transformer:
        return GenericTransformer(fn)

    @staticmethod
    def regex(regex: str | Pattern[str], replacement: str):
        return RegexTransformer(regex, replacement)

    # TODO add more utility functions? e.g. key_value with function as parameter?

    @staticmethod
    def lambda_api():
        return [
            TransformerUtility.key_value("FunctionName"),
            TransformerUtility.jsonpath(
                jsonpath="$..Code.Location",
                value_replacement="<location>",
                reference_replacement=False,
            ),
            # TODO replacing with general function that replces all "datetime" types?
            #  TransformerUtility.key_value("LastModified", reference_replacement=False),
            KeyValueBasedTransformer(_resource_name_transformer, "resource"),
        ]

    @staticmethod
    def cloudformation_api():
        return [
            TransformerUtility.key_value("ChangeSetName"),
            TransformerUtility.key_value("StackName"),
            # TODO
            # TransformerUtility.key_value("CreationTime", reference_replacement=False),
            # TransformerUtility.key_value("LastUpdatedTime", reference_replacement=False),
            KeyValueBasedTransformer(_resource_name_transformer, "resource"),
        ]

    @staticmethod
    def s3_api():
        return [
            TransformerUtility.key_value("Name", value_replacement="bucket-name"),
            # TODO
            # TransformerUtility.key_value("LastModified", reference_replacement=False),
            TransformerUtility.jsonpath(
                jsonpath="$..Owner.DisplayName",
                value_replacement="<display-name>",
                reference_replacement=False,
            ),
            TransformerUtility.jsonpath(
                jsonpath="$..Owner.ID", value_replacement="<owner-id>", reference_replacement=False
            ),
            TransformerUtility.key_value("ETag"),
        ]


def _replace_camel_string_with_hyphen(input_string: str):
    return "".join(["-" + char.lower() if char.isupper() else char for char in input_string]).strip(
        "-"
    )


# TODO does not work yet
def _resource_name_transformer(key: str, val: str) -> str:
    if isinstance(val, str):
        match = re.match(PATTERN_ARN, val)
        if match:
            res = match.groups()[-2].lstrip(":")
            if res.startswith("<") and res.endswith(">"):
                # value was already replaced
                return None
            if "/" in res:
                return res.split("/")[-1]
            if res.startswith("function:"):
                res = res.replace("function:", "")
                if "$" in res:
                    res = res.split("$")[0].rstrip(":")
                return res
            else:
                return res
        return None


# TODO where to move this? added in the snapshot fixture directly, so maybe move there?
SNAPSHOT_BASIC_TRANSFORMER = [
    ResponseMetaDataTransformer(),
    KeyValueBasedTransformer(
        lambda k, v: (
            v
            if (isinstance(v, str) and k.lower().endswith("id") and re.match(PATTERN_UUID, v))
            else None
        ),
        "uuid",
    ),
    RegexTransformer(PATTERN_ISO8601, "date"),
    KeyValueBasedTransformer(
        lambda k, v: (v if isinstance(v, datetime) else None), "datetime", replace_reference=False
    ),
]
