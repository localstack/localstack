import re

from localstack.testing.snapshots.transformer import (
    JsonPathTransformer,
    KeyValueBasedDirectTransformer,
    KeyValueBasedReferenceTransformer,
    RegexMatchReplaceGroupTransformer,
    RegexTransformer,
)

PATTERN_UUID = re.compile(
    r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"
)
PATTERN_ISO8601 = re.compile(
    r"(?:[1-9]\d{3}-(?:(?:0[1-9]|1[0-2])-(?:0[1-9]|1\d|2[0-8])|(?:0[13-9]|1[0-2])-(?:29|30)|(?:0[13578]|1[02])-31)|(?:[1-9]\d(?:0[48]|[2468][048]|[13579][26])|(?:[2468][048]|[13579][26])00)-02-29)T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-][01]\d:?([0-5]\d)?)"
)
PATTERN_ARN_RESOURCENAME_GROUP = re.compile(
    r"arn:[^:\s$\"']*:[^:\s$\"']*:[^:\s$\"']*:[^:\n][^:\s$\"']*:(function:|[a-z]+/)?([^:\s$\"'\{\}<>]*)"
)
# TODO currently unused
# PATTERN_ARN = re.compile(
#     r"arn:(aws[a-zA-Z-]*)?:([a-zA-Z0-9-_.]+)?:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?(:[^:\\\"]+)+"
# )
# PATTERN_S3_URL = re.compile(
#     r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}(\+[0-9]{4})?"
# )
# PATTERN_SQS_URL = re.compile(
#     r"https?://[^/]+/\d{12}/[^/\"]+"
# )  # TODO: differences here between AWS + localstack structure
#
# PATTERN_HASH_256 = re.compile(r"^[A-Fa-f0-9]{64}$")

LAMBDA_TRANSFORMER = [
    # replaces all "FunctionName" values and references
    KeyValueBasedReferenceTransformer(
        lambda k, v: v if k == "FunctionName" else None, replacement="fn-name"
    ),
    # replace all "Location" values with the string "location"
    JsonPathTransformer(json_path="$..Code.Location", replacement="<location>"),
    RegexMatchReplaceGroupTransformer(
        PATTERN_ARN_RESOURCENAME_GROUP, group=2, replacement="resource"
    ),
    KeyValueBasedDirectTransformer(lambda k, _: k == "LastModified", replacement="<date>"),
    KeyValueBasedDirectTransformer(
        lambda k, _: k == "CodeSha256", replacement="<sha256>"
    ),  # TODO could be improved by calculating expected sha
]

SNAPSHOT_BASIC_TRANSFORMER = [
    KeyValueBasedReferenceTransformer(
        lambda k, v: (
            v
            if (isinstance(v, str) and k.lower().endswith("id") and re.match(PATTERN_UUID, v))
            else None
        ),
        "uuid",
    ),
    KeyValueBasedDirectTransformer(
        lambda k, v: v if bool(re.compile(r"HTTPHeaders").match(k)) else None,
        replacement="HTTPHeaders",
    ),
    RegexTransformer(PATTERN_ISO8601, "date"),
]
