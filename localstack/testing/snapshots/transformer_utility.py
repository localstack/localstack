import re
from datetime import datetime
from typing import Optional, Pattern

from localstack.testing.snapshots.transformer import (
    JsonpathTransformer,
    KeyValueBasedTransformer,
    RegexTransformer,
    ResponseMetaDataTransformer,
)

PATTERN_UUID = re.compile(
    r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"
)
PATTERN_ISO8601 = re.compile(
    r"(?:[1-9]\d{3}-(?:(?:0[1-9]|1[0-2])-(?:0[1-9]|1\d|2[0-8])|(?:0[13-9]|1[0-2])-(?:29|30)|(?:0[13578]|1[02])-31)|(?:[1-9]\d(?:0[48]|[2468][048]|[13579][26])|(?:[2468][048]|[13579][26])00)-02-29)T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-][01]\d:?([0-5]\d)?)"
)
PATTERN_ARN = re.compile(r"arn:(aws[a-zA-Z-]*)?:([a-zA-Z0-9-_.]+)?:([^:]+)?:(\d{12})?:(.*)")
PATTERN_ARN_CHANGESET = re.compile(
    r"arn:(aws[a-zA-Z-]*)?:([a-zA-Z0-9-_.]+)?:([^:]+)?:(\d{12})?:changeSet/([^/]+)"
)
PATTERN_LOGSTREAM_ID: Pattern[str] = re.compile(
    # r"\d{4}/\d{2}/\d{2}/\[((\$LATEST)|\d+)\][0-9a-f]{32}" # TODO - this was originally included
    # but some responses from LS look like this: 2022/5/30/[$LATEST]20b0964ab88b01c1 -> might not be correct on LS?
    r"\d{4}/\d{1,2}/\d{1,2}/\[((\$LATEST)|\d+)\][0-9a-f]{16,32}"
)


class TransformerUtility:
    @staticmethod
    def key_value(
        key: str, value_replacement: Optional[str] = None, reference_replacement: bool = True
    ):
        """Creates a new KeyValueBasedTransformer. If the key matches, the value will be replaced.

        :param key: the name of the key which should be replaced
        :param value_replacement: the value which will replace the original value.
        By default it is the key-name in lowercase, separated with hyphen
        :param reference_replacement: if False, only the original value for this key will be replaced.
        If True all references of this value will be replaced (using a regex pattern), for the entire test case.
        In this case, the replaced value will be nummerated as well.
        Default: True

        :return: KeyValueBasedTransformer
        """
        return KeyValueBasedTransformer(
            lambda k, v: v if k == key else None,
            replacement=value_replacement or _replace_camel_string_with_hyphen(key),
            replace_reference=reference_replacement,
        )

    @staticmethod
    def jsonpath(jsonpath: str, value_replacement: str, reference_replacement: bool = True):
        """Creates a new JsonpathTransformer. If the jsonpath matches, the value will be replaced.

        :param jsonpath: the jsonpath that should be matched
        :param value_replacement: the value which will replace the original value.
        By default it is the key-name in lowercase, separated with hyphen
        :param reference_replacement: if False, only the original value for this key will be replaced.
        If True all references of this value will be replaced (using a regex pattern), for the entire test case.
        In this case, the replaced value will be nummerated as well.
        Default: True

        :return: JsonpathTransformer
        """
        return JsonpathTransformer(
            jsonpath=jsonpath,
            replacement=value_replacement,
            replace_reference=reference_replacement,
        )

    @staticmethod
    def regex(regex: str | Pattern[str], replacement: str):
        """Creates a new RegexTransformer. All matches in the string-converted dict will be replaced.

        :param regex: the regex that should be matched
        :param replacement: the value which will replace the original value.

        :return: RegexTransformer
        """
        return RegexTransformer(regex, replacement)

    # TODO add more utility functions? e.g. key_value with function as parameter?

    @staticmethod
    def lambda_api():
        """
        :return: array with Transformers, for lambda api.
        """
        return [
            TransformerUtility.key_value("FunctionName"),
            TransformerUtility.jsonpath(
                jsonpath="$..Code.Location",
                value_replacement="<location>",
                reference_replacement=False,
            ),
            KeyValueBasedTransformer(_resource_name_transformer, "resource"),
            KeyValueBasedTransformer(
                _log_stream_name_transformer, "log-stream-name", replace_reference=True
            ),
        ]

    @staticmethod
    def cloudformation_api():
        """
        :return: array with Transformers, for cloudformation api.
        """
        return [
            TransformerUtility.key_value("ChangeSetName"),
            TransformerUtility.key_value("StackName"),
            KeyValueBasedTransformer(_resource_name_transformer, "resource"),
            KeyValueBasedTransformer(_change_set_id_transformer, "change-set-id"),
        ]

    @staticmethod
    def iam_api():
        """
        :return: array with Transformers, for iam api.
        """
        return [TransformerUtility.key_value("UserName"), TransformerUtility.key_value("UserId")]

    @staticmethod
    def s3_api():
        """
        :return: array with Transformers, for s3 api.
        """
        return [
            TransformerUtility.key_value("Name", value_replacement="bucket-name"),
            TransformerUtility.jsonpath(
                jsonpath="$..Owner.DisplayName",
                value_replacement="<display-name>",
                reference_replacement=False,
            ),
            TransformerUtility.jsonpath(
                jsonpath="$..Owner.ID", value_replacement="<owner-id>", reference_replacement=False
            ),
            # for s3 notifications:
            TransformerUtility.jsonpath(
                "$..responseElements.x-amz-id-2", "amz-id", reference_replacement=False
            ),
            TransformerUtility.jsonpath(
                "$..responseElements.x-amz-request-id",
                "amz-request-id",
                reference_replacement=False,
            ),
            TransformerUtility.jsonpath("$..s3.configurationId", "config-id"),
            TransformerUtility.jsonpath(
                "$..s3.object.sequencer", "sequencer", reference_replacement=False
            ),
            TransformerUtility.jsonpath("$..s3.bucket.ownerIdentity.principalId", "principal-id"),
            TransformerUtility.jsonpath("$..userIdentity.principalId", "principal-id"),
            TransformerUtility.jsonpath("$..requestParameters.sourceIPAddress", "ip-address"),
            TransformerUtility.jsonpath(
                "$..s3.object.versionId",
                "version-id",
                reference_replacement=False,
            ),
        ]

    @staticmethod
    def sqs_api():
        """
        :return: array with Transformers, for sqs api.
        """
        return [
            TransformerUtility.key_value("ReceiptHandle"),
            TransformerUtility.key_value("SenderId"),
            TransformerUtility.jsonpath("$..MessageAttributes.RequestID.StringValue", "request-id"),
            KeyValueBasedTransformer(_resource_name_transformer, "resource"),
            KeyValueBasedTransformer(_signing_cert_url_token_transformer, replacement="token"),
            KeyValueBasedTransformer(
                _sns_pem_file_token_transformer, replacement="signing-cert-file"
            ),
            # replaces the domain in "UnsubscribeURL"
            TransformerUtility.regex(
                re.compile(
                    r"(?<=UnsubscribeURL[\"|']:\s[\"|'])(https?.*?)(?=/\?Action=Unsubscribe)"
                ),
                replacement="<unsubscribe-domain>",
            ),
        ]

    # TODO add example
    # @staticmethod
    # def custom(fn: Callable[[dict], dict]) -> Transformer:
    #     return GenericTransformer(fn)


def _sns_pem_file_token_transformer(key: str, val: str) -> str:
    if isinstance(val, str) and key == "SigningCertURL":
        pattern = re.compile(r".*SimpleNotificationService-(.*)?\.pem")
        match = re.match(pattern, val)
        if match:
            return match.groups()[0]


def _signing_cert_url_token_transformer(key: str, val: str) -> str:
    if isinstance(val, str) and key == "UnsubscribeURL":
        pattern = re.compile(r".*(?<=\?Action=Unsubscribe&SubscriptionArn=).*:(.*)")
        match = re.match(pattern, val)
        if match:
            return match.groups()[0]


def _replace_camel_string_with_hyphen(input_string: str):
    return "".join(["-" + char.lower() if char.isupper() else char for char in input_string]).strip(
        "-"
    )


def _log_stream_name_transformer(key: str, val: str) -> str:
    if isinstance(val, str) and (key == "log_stream_name" or key == "logStreamName"):
        match = re.match(PATTERN_LOGSTREAM_ID, val)
        if match:
            return val
    return None


def _resource_name_transformer(key: str, val: str) -> str:
    if isinstance(val, str):
        match = re.match(PATTERN_ARN, val)
        if match:
            res = match.groups()[-1]
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
            if ":" in res:
                return res.split(":")[-1]  # TODO might not work for every replacement
            return res
        return None


def _change_set_id_transformer(key: str, val: str) -> str:
    if key == "Id" and isinstance(val, str):
        match = re.match(PATTERN_ARN_CHANGESET, val)
        if match:
            return match.groups()[-1]
    return None


# TODO maybe move to a different place?
# Basic Transformation - added automatically to each snapshot (in the fixture)
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
    KeyValueBasedTransformer(
        lambda k, v: str(v)
        if (
            re.compile(r"^.*timestamp.*$", flags=re.IGNORECASE).match(k)
            or k in ("creationTime", "ingestionTime")
        )
        and not PATTERN_ISO8601.match(str(v))
        else None,
        "timestamp",
        replace_reference=False,
    ),
]
