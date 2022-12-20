import logging
import re
from datetime import datetime
from typing import Optional, Pattern

from localstack.aws.api.secretsmanager import CreateSecretResponse
from localstack.testing.snapshots.transformer import (
    JsonpathTransformer,
    KeyValueBasedTransformer,
    RegexTransformer,
    ResponseMetaDataTransformer,
    SortingTransformer,
)
from localstack.utils.net import IP_REGEX

LOG = logging.getLogger(__name__)


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
    r"\d{4}/\d{1,2}/\d{1,2}/\[((\$LATEST)|\d+)\][0-9a-f]{8,32}"
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
    def resource_name(replacement_name: str = "resource"):
        """Creates a new KeyValueBasedTransformer for the resource name.

        :param replacement_name ARN of a resource to extract name from
        :return: KeyValueBasedTransformer
        """
        return KeyValueBasedTransformer(_resource_name_transformer, replacement_name)

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
            TransformerUtility.key_value(
                "CodeSize", value_replacement="<code-size>", reference_replacement=False
            ),
            TransformerUtility.jsonpath(
                jsonpath="$..Code.Location",
                value_replacement="<location>",
                reference_replacement=False,
            ),
            TransformerUtility.jsonpath(
                jsonpath="$..Content.Location",
                value_replacement="<layer-location>",
                reference_replacement=False,
            ),
            KeyValueBasedTransformer(_resource_name_transformer, "resource"),
            KeyValueBasedTransformer(
                _log_stream_name_transformer, "log-stream-name", replace_reference=True
            ),
        ]

    @staticmethod
    def apigateway_api():
        return [
            TransformerUtility.key_value("id"),
            TransformerUtility.key_value("name"),
        ]

    @staticmethod
    def apigateway_proxy_event():
        return [
            TransformerUtility.key_value("extendedRequestId"),
            TransformerUtility.key_value("resourceId"),
            TransformerUtility.key_value("sourceIp"),
            TransformerUtility.jsonpath("$..headers.X-Amz-Cf-Id", value_replacement="cf-id"),
            TransformerUtility.jsonpath(
                "$..headers.CloudFront-Viewer-ASN", value_replacement="cloudfront-asn"
            ),
            TransformerUtility.jsonpath(
                "$..headers.CloudFront-Viewer-Country", value_replacement="cloudfront-country"
            ),
            TransformerUtility.jsonpath("$..headers.Via", value_replacement="via"),
            TransformerUtility.jsonpath("$..headers.X-Amzn-Trace-Id", value_replacement="trace-id"),
            TransformerUtility.jsonpath(
                "$..requestContext.requestTime",
                value_replacement="<request-time>",
                reference_replacement=False,
            ),
            KeyValueBasedTransformer(
                lambda k, v: str(v) if k == "requestTimeEpoch" else None,
                "<request-time-epoch>",
                replace_reference=False,
            ),
            TransformerUtility.regex(IP_REGEX.strip("^$"), "<ip>"),
        ]

    @staticmethod
    def cloudformation_api():
        """
        :return: array with Transformers, for cloudformation api.
        """
        return [
            KeyValueBasedTransformer(_resource_name_transformer, "resource"),
            KeyValueBasedTransformer(_change_set_id_transformer, "change-set-id"),
            TransformerUtility.key_value("ChangeSetName"),
            TransformerUtility.key_value("ChangeSetId"),
            TransformerUtility.key_value("StackName"),
        ]

    @staticmethod
    def dynamodb_api():
        """
        :return: array with Transformers, for dynamodb api.
        """
        return [
            RegexTransformer(
                r"([a-zA-Z0-9-_.]*)?test_table_([a-zA-Z0-9-_.]*)?", replacement="<test-table>"
            ),
        ]

    @staticmethod
    def iam_api():
        """
        :return: array with Transformers, for iam api.
        """
        return [TransformerUtility.key_value("UserName"), TransformerUtility.key_value("UserId")]

    @staticmethod
    def transcribe_api():
        """
        :return: array with Transformers, for iam api.
        """
        return [
            RegexTransformer(
                r"([a-zA-Z0-9-_.]*)?\/test-bucket-([a-zA-Z0-9-_.]*)?", replacement="<test-bucket>"
            ),
            TransformerUtility.key_value("TranscriptionJobName", "transcription-job"),
            TransformerUtility.jsonpath(
                jsonpath="$..Transcript..TranscriptFileUri",
                value_replacement="<transcript-file-uri>",
                reference_replacement=False,
            ),
            TransformerUtility.key_value("NextToken", "token", reference_replacement=False),
        ]

    @staticmethod
    def s3_api():
        """
        :return: array with Transformers, for s3 api.
        """

        s3 = [
            TransformerUtility.key_value("Name", value_replacement="bucket-name"),
            TransformerUtility.key_value("BucketName"),
            TransformerUtility.key_value("VersionId"),
            TransformerUtility.jsonpath(
                jsonpath="$..Owner.DisplayName",
                value_replacement="<display-name>",
                reference_replacement=False,
            ),
            TransformerUtility.jsonpath(
                jsonpath="$..Owner.ID", value_replacement="<owner-id>", reference_replacement=False
            ),
        ]
        # for s3 notifications:
        s3.extend(TransformerUtility.s3_notifications_transformer())
        return s3

    @staticmethod
    def s3_notifications_transformer():
        return [
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
    def kinesis_api():
        """
        :return: array with Transformers, for kinesis api.
        """
        return [
            JsonpathTransformer(
                jsonpath="$..Records..SequenceNumber",
                replacement="sequence_number",
                replace_reference=True,
            ),
            TransformerUtility.key_value("StartingSequenceNumber", "starting_sequence_number"),
            TransformerUtility.key_value("ShardId", "shard_id"),
            TransformerUtility.key_value(
                "EndingHashKey", "ending_hash", reference_replacement=False
            ),
            TransformerUtility.key_value(
                "StartingHashKey", "starting_hash", reference_replacement=False
            ),
            TransformerUtility.key_value(_resource_name_transformer, "ConsumerARN"),
            RegexTransformer(
                r"([a-zA-Z0-9-_.]*)?\/consumer:([0-9-_.]*)?",
                replacement="<stream-consumer>",
            ),
            RegexTransformer(
                r"([a-zA-Z0-9-_.]*)?\/test-stream-([a-zA-Z0-9-_.]*)?",
                replacement="<stream-name>",
            ),
            TransformerUtility.key_value(
                "ContinuationSequenceNumber", "<continuation_sequence_number>"
            ),
        ]

    @staticmethod
    def route53resolver_api():
        """
        :return: array with Transformers, for route53resolver api.
        """
        return [
            TransformerUtility.key_value(
                "SecurityGroupIds", value_replacement="sg-ids", reference_replacement=False
            ),
            TransformerUtility.key_value("Id"),
            TransformerUtility.key_value("HostVPCId", "host-vpc-id"),
            KeyValueBasedTransformer(_resource_name_transformer, "Arn"),
            TransformerUtility.key_value("CreatorRequestId"),
            TransformerUtility.key_value("StatusMessage", reference_replacement=False),
        ]

    @staticmethod
    def sqs_api():
        """
        :return: array with Transformers, for sqs api.
        """
        return [
            TransformerUtility.key_value("ReceiptHandle"),
            TransformerUtility.key_value(
                "SenderId"
            ),  # TODO: flaky against AWS (e.g. /Attributes/SenderId '<sender-id:1>' → '<sender-id:2>' ... (expected → actual))
            TransformerUtility.key_value("SequenceNumber"),
            TransformerUtility.jsonpath("$..MessageAttributes.RequestID.StringValue", "request-id"),
            KeyValueBasedTransformer(_resource_name_transformer, "resource"),
        ]

    @staticmethod
    def sns_api():
        """
        :return: array with Transformers, for sns api.
        """
        return [
            TransformerUtility.key_value("ReceiptHandle"),
            TransformerUtility.key_value("SequenceNumber"),  # this might need to be in SQS
            TransformerUtility.key_value(
                "Signature", value_replacement="<signature>", reference_replacement=False
            ),
            # the body of SNS messages contains a timestamp, need to ignore the hash
            TransformerUtility.key_value("MD5OfBody", "<md5-hash>", reference_replacement=False),
            # this can interfere in ARN with the accountID
            TransformerUtility.key_value(
                "SenderId", value_replacement="<sender-id>", reference_replacement=False
            ),
            KeyValueBasedTransformer(
                _sns_pem_file_token_transformer,
                replacement="signing-cert-file",
            ),
            # replaces the domain in "UnsubscribeURL" URL (KeyValue won't work as it replaces reference, and if
            # replace_reference is False, then it replaces the whole key
            # this will be able to use a KeyValue based once we provide a certificate for message signing in SNS
            # a match must be made case-insensitive because the key casing is different from lambda notifications
            RegexTransformer(
                r"(?<=(?i)UnsubscribeURL[\"|']:\s[\"|'])(https?.*?)(?=/\?Action=Unsubscribe)",
                replacement="<unsubscribe-domain>",
            ),
            KeyValueBasedTransformer(_resource_name_transformer, "resource"),
            # add a special transformer with 'resource' replacement for SubscriptionARN in UnsubscribeURL
            KeyValueBasedTransformer(
                _sns_unsubscribe_url_subscription_arn_transformer, replacement="resource"
            ),
        ]

    @staticmethod
    def cloudwatch_api():
        """
        :return: array with Transformers, for cloudwatch api.
        """
        return [
            TransformerUtility.key_value("AlarmName"),
            KeyValueBasedTransformer(_resource_name_transformer, "SubscriptionArn"),
            TransformerUtility.key_value("Region", "region-name-full"),
        ]

    @staticmethod
    def secretsmanager_api():
        return [
            KeyValueBasedTransformer(
                lambda k, v: (
                    k
                    if (isinstance(k, str) and isinstance(v, list) and re.match(PATTERN_UUID, k))
                    else None
                ),
                "version_uuid",
            ),
            KeyValueBasedTransformer(
                lambda k, v: (
                    v
                    if (
                        isinstance(k, str)
                        and k == "VersionId"
                        and isinstance(v, str)
                        and re.match(PATTERN_UUID, v)
                    )
                    else None
                ),
                "version_uuid",
            ),
            SortingTransformer("VersionStages"),
            SortingTransformer("Versions", lambda e: e.get("CreatedDate")),
        ]

    @staticmethod
    def secretsmanager_secret_id_arn(create_secret_res: CreateSecretResponse, index: int):
        secret_id_repl = f"<SecretId-{index}idx>"
        arn_part_repl = f"<ArnPart-{index}idx>"

        secret_id: str = create_secret_res["Name"]
        arn_part: str = "".join(create_secret_res["ARN"].rpartition("-")[-2:])

        return [
            RegexTransformer(arn_part, arn_part_repl),
            RegexTransformer(secret_id, secret_id_repl),
        ]

    # TODO add example
    # @staticmethod
    # def custom(fn: Callable[[dict], dict]) -> Transformer:
    #     return GenericTransformer(fn)


def _sns_pem_file_token_transformer(key: str, val: str) -> str:
    if isinstance(val, str) and key.lower() == "SigningCertURL".lower():
        pattern = re.compile(r".*SimpleNotificationService-(.*\.pem)")
        match = re.match(pattern, val)
        if match:
            return match.groups()[0]


def _sns_unsubscribe_url_subscription_arn_transformer(key: str, val: str) -> str:
    if isinstance(val, str) and key.lower() == "UnsubscribeURL".lower():
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


# TODO: actual and declared type diverge
def _resource_name_transformer(key: str, val: str) -> str:
    if isinstance(val, str):
        match = re.match(PATTERN_ARN, val)
        if match:
            res = match.groups()[-1]
            if res.startswith("<") and res.endswith(">"):
                # value was already replaced
                # TODO: this isn't enforced or unfortunately even upheld via standard right now
                return None
            if ":changeSet/" in val:
                return val.split(":changeSet/")[-1]
            if "/" in res:
                return res.split("/")[-1]
            if res.startswith("function:"):
                res = res.replace("function:", "")
                if "$" in res:
                    res = res.split("$")[0].rstrip(":")
                return res
            if res.startswith("layer:"):
                # extract layer name from arn
                match res.split(":"):
                    case _, layer_name, _:  # noqa
                        return layer_name  # noqa
                    case _, layer_name:  # noqa
                        return layer_name  # noqa
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
