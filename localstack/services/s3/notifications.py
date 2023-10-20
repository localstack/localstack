import datetime
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, TypedDict, Union
from urllib.parse import quote

from botocore.exceptions import ClientError
from moto.s3.models import FakeBucket, FakeDeleteMarker, FakeKey

from localstack.aws.api import RequestContext
from localstack.aws.api.events import PutEventsRequestEntry
from localstack.aws.api.lambda_ import InvocationType
from localstack.aws.api.s3 import (
    AccountId,
    BucketName,
    BucketRegion,
    Event,
    EventBridgeConfiguration,
    EventList,
    LambdaFunctionArn,
    LambdaFunctionConfiguration,
    NoSuchKey,
    NotificationConfiguration,
    NotificationConfigurationFilter,
    NotificationId,
    ObjectKey,
    QueueArn,
    QueueConfiguration,
    StorageClass,
    TopicArn,
    TopicConfiguration,
)
from localstack.aws.connect import connect_to
from localstack.services.s3.models import get_moto_s3_backend
from localstack.services.s3.utils import (
    _create_invalid_argument_exc,
    get_bucket_from_moto,
    get_key_from_moto_bucket,
)
from localstack.services.s3.v3.models import S3Bucket, S3DeleteMarker, S3Object
from localstack.utils.aws import arns
from localstack.utils.aws.arns import parse_arn, s3_bucket_arn
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.strings import short_uid
from localstack.utils.time import parse_timestamp, timestamp_millis

LOG = logging.getLogger(__name__)

EVENT_OPERATION_MAP = {
    "PutObject": Event.s3_ObjectCreated_Put,
    "CopyObject": Event.s3_ObjectCreated_Copy,
    "CompleteMultipartUpload": Event.s3_ObjectCreated_CompleteMultipartUpload,
    "PostObject": Event.s3_ObjectCreated_Post,
    "PutObjectTagging": Event.s3_ObjectTagging_Put,
    "DeleteObjectTagging": Event.s3_ObjectTagging_Delete,
    "DeleteObject": Event.s3_ObjectRemoved_Delete,
    "DeleteObjects": Event.s3_ObjectRemoved_Delete,
    "PutObjectAcl": Event.s3_ObjectAcl_Put,
    "RestoreObject": Event.s3_ObjectRestore_Post,
}

HEADER_AMZN_XRAY = "X-Amzn-Trace-Id"


class S3NotificationContent(TypedDict):
    s3SchemaVersion: str
    configurationId: NotificationId
    bucket: Dict[str, str]  # todo
    object: Dict[str, Union[str, int]]  # todo


class EventRecord(TypedDict):
    eventVersion: str
    eventSource: str
    awsRegion: str
    eventTime: str
    eventName: str
    userIdentity: Dict[str, str]
    requestParameters: Dict[str, str]
    responseElements: Dict[str, str]
    s3: S3NotificationContent


class Notification(TypedDict):
    Records: List[EventRecord]


@dataclass
class S3EventNotificationContext:
    request_id: str
    event_type: str
    event_time: datetime.datetime
    account_id: str
    region: str
    bucket_name: BucketName
    key_name: ObjectKey
    xray: str
    bucket_location: BucketRegion
    bucket_account_id: AccountId
    caller: AccountId
    key_size: int
    key_etag: str
    key_version_id: str
    key_expiry: datetime.datetime
    key_storage_class: Optional[StorageClass]

    @classmethod
    def from_request_context(
        cls,
        request_context: RequestContext,
        key_name: str = None,
        version_id: str = None,
        allow_non_existing_key=False,
    ) -> "S3EventNotificationContext":
        """
        Create an S3EventNotificationContext from a RequestContext.
        The key is not always present in the request context depending on the event type. In that case, we can use
        a provided one.
        :param request_context: RequestContext
        :param key_name: Optional, in case it's not provided in the RequestContext
        :param version_id: Optional, can be given to get the key version in case of deletion
        :param allow_non_existing_key: Optional, indicates that a dummy Key should be created, if it does not exist (required for delete_objects)
        :return: S3EventNotificationContext
        """
        bucket_name = request_context.service_request["Bucket"]
        moto_backend = get_moto_s3_backend(request_context)
        bucket: FakeBucket = get_bucket_from_moto(moto_backend, bucket=bucket_name)
        try:
            key: FakeKey = get_key_from_moto_bucket(
                moto_bucket=bucket,
                key=key_name or request_context.service_request["Key"],
                version_id=version_id,
            )
        except NoSuchKey as ex:
            if allow_non_existing_key:
                key: FakeKey = FakeKey(key_name, "")
            else:
                raise ex

        # TODO: test notification format when the concerned key is FakeDeleteMarker
        # it might not send notification, or s3:ObjectRemoved:DeleteMarkerCreated which we don't support
        if isinstance(key, FakeDeleteMarker):
            etag = ""
            key_size = 0
            key_expiry = None
            storage_class = ""
        else:
            etag = key.etag.strip('"')
            key_size = key.contentsize
            key_expiry = key._expiry
            storage_class = key.storage_class

        return cls(
            request_id=request_context.request_id,
            event_type=EVENT_OPERATION_MAP.get(request_context.operation.wire_name, ""),
            event_time=datetime.datetime.now(),
            account_id=request_context.account_id,
            region=request_context.region,
            caller=request_context.account_id,  # TODO: use it for `userIdentity`
            bucket_name=bucket_name,
            bucket_location=bucket.location,
            bucket_account_id=bucket.account_id,  # TODO: use it for bucket owner identity
            key_name=quote(key.name),
            key_etag=etag,
            key_size=key_size,
            key_expiry=key_expiry,
            key_storage_class=storage_class,
            key_version_id=key.version_id if bucket.is_versioned else None,  # todo: check this?
            xray=request_context.request.headers.get(HEADER_AMZN_XRAY),
        )

    @classmethod
    def from_request_context_native(
        cls,
        request_context: RequestContext,
        s3_bucket: S3Bucket,
        s3_object: S3Object | S3DeleteMarker,
    ) -> "S3EventNotificationContext":
        """
        Create an S3EventNotificationContext from a RequestContext.
        The key is not always present in the request context depending on the event type. In that case, we can use
        a provided one.
        :param request_context: RequestContext
        :param s3_bucket: S3Bucket
        :param s3_object: S3Object passed directly to the context
        :return: S3EventNotificationContext
        """
        bucket_name = request_context.service_request["Bucket"]

        # TODO: test notification format when the concerned key is FakeDeleteMarker
        # it might not send notification, or s3:ObjectRemoved:DeleteMarkerCreated which we don't support yet
        if isinstance(s3_object, S3DeleteMarker):
            etag = ""
            key_size = 0
            key_expiry = None
            storage_class = ""
        else:
            etag = s3_object.etag.strip('"')
            key_size = s3_object.size
            key_expiry = s3_object.expires
            storage_class = s3_object.storage_class

        return cls(
            request_id=request_context.request_id,
            event_type=EVENT_OPERATION_MAP.get(request_context.operation.wire_name, ""),
            event_time=datetime.datetime.now(),
            account_id=request_context.account_id,
            region=request_context.region,
            caller=request_context.account_id,  # TODO: use it for `userIdentity`
            bucket_name=bucket_name,
            bucket_location=s3_bucket.bucket_region,
            bucket_account_id=s3_bucket.bucket_account_id,  # TODO: use it for bucket owner identity
            key_name=quote(s3_object.key),
            key_etag=etag,
            key_size=key_size,
            key_expiry=key_expiry,
            key_storage_class=storage_class,
            key_version_id=s3_object.version_id
            if s3_bucket.versioning_status
            else None,  # todo: check this?
            xray=request_context.request.headers.get(HEADER_AMZN_XRAY),
        )


@dataclass
class BucketVerificationContext:
    """
    Context object for data required for sending a `s3:TestEvent` like message.
    """

    request_id: str
    bucket_name: str
    configuration: Dict
    skip_destination_validation: bool


def _matching_event(events: EventList, event_name: str) -> bool:
    """
    See: https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html
    Checks if the event is part of the NotificationConfiguration, and returns if the event should be notified for
    this configuration
    :param events: the list of events of the NotificationConfiguration
    :param event_name: the event type, like s3:ObjectCreated:* or s3:ObjectRemoved:Delete
    :return: boolean indicating if the event should be sent to the notifiers
    """
    if event_name in events:
        return True
    wildcard_pattern = f"{event_name[0:event_name.rindex(':')]}:*"
    return wildcard_pattern in events


def _matching_filter(
    notification_filter: Optional[NotificationConfigurationFilter], key_name: str
) -> bool:
    """
    See: https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-filtering.html
    S3 allows filtering notification events with rules about the key name.
    If the key does not have a filter rule, or if it matches the rule, then returns that the event should be sent
    :param notification_filter: the Filter structure from NotificationConfiguration
    :param key_name: the key name of the key concerned by the event
    :return: boolean indicating if the key name matches the rules and the event should be sent
    """
    # TODO: implement wildcard filtering
    if not notification_filter or not notification_filter.get("Key", {}).get("FilterRules"):
        return True
    filter_rules = notification_filter.get("Key").get("FilterRules")
    for rule in filter_rules:
        name = rule.get("Name", "").lower()
        value = rule.get("Value", "")
        if name == "prefix" and not key_name.startswith(value):
            return False
        elif name == "suffix" and not key_name.endswith(value):
            return False

    return True


class BaseNotifier:
    service_name: str

    def notify(self, ctx: S3EventNotificationContext, config: Dict):
        raise NotImplementedError

    @staticmethod
    def should_notify(ctx: S3EventNotificationContext, config: Dict) -> bool:
        """
        Helper method checking if the event should be notified to the configured notifiers from the configuration
        :param ctx: S3EventNotificationContext
        :param config: the notification config
        :return: if the notifier should send the event or not
        """
        return _matching_event(config["Events"], ctx.event_type) and _matching_filter(
            config.get("Filter"), ctx.key_name
        )

    @staticmethod
    def _get_arn_value_and_name(notifier_configuration: Dict) -> Tuple[str, str]:
        raise NotImplementedError

    def validate_configuration_for_notifier(
        self,
        configurations: List[Dict],
        skip_destination_validation: bool,
        context: RequestContext,
        bucket_name: str,
    ):
        for configuration in configurations:
            self._validate_notification(
                BucketVerificationContext(
                    configuration=configuration,
                    bucket_name=bucket_name,
                    request_id=context.request_id,
                    skip_destination_validation=skip_destination_validation,
                )
            )

    def _verify_target(self, target_arn: str, verification_ctx: BucketVerificationContext) -> None:
        raise NotImplementedError

    def _validate_notification(self, verification_ctx: BucketVerificationContext):
        """
        Validates the notification configuration
        - setting default ID if not provided
        - validate the arn pattern
        - validating the Rule names (and normalizing to capitalized)
        - check if the filter value is not empty
        :param configuration: a configuration for a notifier, like QueueConfiguration for SQS or
        TopicConfiguration for SNS
        :param skip_destination_validation: allow skipping the validation of the target
        :raises InvalidArgument if the rule is not valid, infos in ArgumentName and ArgumentValue members
        :return:
        """
        configuration = verification_ctx.configuration
        # id's can be set the request, but need to be auto-generated if they are not provided
        if not configuration.get("Id"):
            configuration["Id"] = short_uid()

        arn, argument_name = self._get_arn_value_and_name(configuration)

        if not arn.startswith(f"arn:aws:{self.service_name}:"):
            raise _create_invalid_argument_exc(
                "The ARN could not be parsed", name=argument_name, value=arn
            )
        if not verification_ctx.skip_destination_validation:
            self._verify_target(arn, verification_ctx)

        if filter_rules := configuration.get("Filter", {}).get("Key", {}).get("FilterRules"):
            for rule in filter_rules:
                rule["Name"] = rule["Name"].capitalize()
                if rule["Name"] not in ["Suffix", "Prefix"]:
                    raise _create_invalid_argument_exc(
                        "filter rule name must be either prefix or suffix",
                        rule["Name"],
                        rule["Value"],
                    )
                if not rule["Value"]:
                    raise _create_invalid_argument_exc(
                        "filter value cannot be empty", rule["Name"], rule["Value"]
                    )

    @staticmethod
    def _get_test_payload(verification_ctx: BucketVerificationContext):
        return {
            "Service": "Amazon S3",
            "Event": "s3:TestEvent",
            "Time": timestamp_millis(),
            "Bucket": verification_ctx.bucket_name,
            "RequestId": verification_ctx.request_id,
            "HostId": "eftixk72aD6Ap51TnqcoF8eFidJG9Z/2",
        }

    @staticmethod
    def _get_event_payload(
        ctx: S3EventNotificationContext, config_id: NotificationId
    ) -> Notification:
        # Based on: http://docs.aws.amazon.com/AmazonS3/latest/dev/notification-content-structure.html
        # TODO: think about caching or generating the payload only once, because only the config_id changes
        #  except if it is EventBridge. Check that.
        record = EventRecord(
            eventVersion="2.1",
            eventSource="aws:s3",
            awsRegion=ctx.bucket_location,
            eventTime=timestamp_millis(ctx.event_time),
            eventName=ctx.event_type.removeprefix("s3:"),
            userIdentity={"principalId": "AIDAJDPLRKLG7UEXAMPLE"},  # TODO: use the real one?
            requestParameters={
                "sourceIPAddress": "127.0.0.1"
            },  # TODO sourceIPAddress was previously extracted from headers ("X-Forwarded-For")
            responseElements={
                "x-amz-request-id": short_uid(),
                # todo this one is tricky, as it's generated by the response serializer...
                "x-amz-id-2": "eftixk72aD6Ap51TnqcoF8eFidJG9Z/2",  # Amazon S3 host that processed the request
            },
            s3=S3NotificationContent(
                s3SchemaVersion="1.0",
                configurationId=config_id,
                bucket={
                    "name": ctx.bucket_name,
                    "ownerIdentity": {
                        "principalId": "A3NL1KOZZKExample"
                    },  # TODO: use proper principal?
                    "arn": f"arn:aws:s3:::{ctx.bucket_name}",
                },
                object={
                    "key": ctx.key_name,
                    "sequencer": "0055AED6DCD90281E5",
                },
            ),
        )

        if ctx.key_version_id:
            # object version if bucket is versioning-enabled, otherwise null
            record["s3"]["object"]["versionId"] = ctx.key_version_id

        event_type = ctx.event_type.lower()
        if any(e in event_type for e in ("created", "restore")):
            record["s3"]["object"]["size"] = ctx.key_size
            record["s3"]["object"]["eTag"] = ctx.key_etag
        if "ObjectTagging" in ctx.event_type or "ObjectAcl" in ctx.event_type:
            record["eventVersion"] = "2.3"
            record["s3"]["object"]["eTag"] = ctx.key_etag
            record["s3"]["object"].pop("sequencer")

        if "objectrestore:completed" in event_type:
            record["glacierEventData"] = {
                "restoreEventData": {
                    "lifecycleRestorationExpiryTime": timestamp_millis(ctx.key_expiry),
                    "lifecycleRestoreStorageClass": ctx.key_storage_class,
                }
            }
            record["userIdentity"][
                "principalId"
            ] = "AmazonCustomer:A3NL1KOZZKExample"  # TODO: use proper principal?
            # a bit hacky, it is to ensure the eventTime is a bit after the `Post` event, as its instant in LS
            # the best would be to delay the publishing of the event
            event_time = parse_timestamp(record["eventTime"]) + datetime.timedelta(milliseconds=500)
            record["eventTime"] = timestamp_millis(event_time)

        return {"Records": [record]}


class SqsNotifier(BaseNotifier):
    service_name = "sqs"

    @staticmethod
    def _get_arn_value_and_name(queue_configuration: QueueConfiguration) -> Tuple[QueueArn, str]:
        return queue_configuration.get("QueueArn", ""), "QueueArn"

    def _verify_target(self, target_arn: str, verification_ctx: BucketVerificationContext) -> None:
        arn_data = parse_arn(target_arn)
        sqs_client = connect_to(
            aws_access_key_id=arn_data["account"], region_name=arn_data["region"]
        ).sqs
        # test if the destination exists (done on AWS side, no permission required)
        try:
            queue_url = sqs_client.get_queue_url(
                QueueName=arn_data["resource"], QueueOwnerAWSAccountId=arn_data["account"]
            )["QueueUrl"]
        except ClientError:
            LOG.exception("Could not validate the notification destination %s", target_arn)
            raise _create_invalid_argument_exc(
                "Unable to validate the following destination configurations",
                name=target_arn,
                value="The destination queue does not exist",
            )
        # send test event with the request metadata for permissions
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html#supported-notification-event-types
        sqs_client = connect_to(region_name=arn_data["region"]).sqs.request_metadata(
            source_arn=s3_bucket_arn(verification_ctx.bucket_name),
            service_principal=ServicePrincipal.s3,
        )
        test_payload = self._get_test_payload(verification_ctx)
        try:
            sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(test_payload))
        except ClientError as e:
            LOG.error(
                'Unable to send test notification for S3 bucket "%s" to SQS queue "%s"',
                verification_ctx.bucket_name,
                target_arn,
            )
            raise _create_invalid_argument_exc(
                "Unable to validate the following destination configurations",
                name=target_arn,
                value="Permissions on the destination queue do not allow S3 to publish notifications from this bucket",
            ) from e

    def notify(self, ctx: S3EventNotificationContext, config: QueueConfiguration):
        event_payload = self._get_event_payload(ctx, config.get("Id"))
        message = json.dumps(event_payload)
        queue_arn = config["QueueArn"]

        parsed_arn = parse_arn(queue_arn)
        sqs_client = connect_to(region_name=parsed_arn["region"]).sqs.request_metadata(
            source_arn=s3_bucket_arn(ctx.bucket_name), service_principal=ServicePrincipal.s3
        )
        try:
            queue_url = arns.sqs_queue_url_for_arn(queue_arn)
            system_attributes = {}
            if ctx.xray:
                system_attributes["AWSTraceHeader"] = {
                    "DataType": "String",
                    "StringValue": ctx.xray,
                }
            sqs_client.send_message(
                QueueUrl=queue_url,
                MessageBody=message,
                MessageSystemAttributes=system_attributes,
            )
        except Exception:
            LOG.exception(
                'Unable to send notification for S3 bucket "%s" to SQS queue "%s"',
                ctx.bucket_name,
                parsed_arn["resource"],
            )


class SnsNotifier(BaseNotifier):
    service_name = "sns"

    @staticmethod
    def _get_arn_value_and_name(topic_configuration: TopicConfiguration) -> [TopicArn, str]:
        return topic_configuration.get("TopicArn", ""), "TopicArn"

    def _verify_target(self, target_arn: str, verification_ctx: BucketVerificationContext) -> None:
        arn_data = parse_arn(target_arn)
        sns_client = connect_to(
            aws_access_key_id=arn_data["account"], region_name=arn_data["region"]
        ).sns
        try:
            sns_client.get_topic_attributes(TopicArn=target_arn)
        except ClientError:
            raise _create_invalid_argument_exc(
                "Unable to validate the following destination configurations",
                name=target_arn,
                value="The destination topic does not exist",
            )

        sns_client = connect_to(region_name=arn_data["region"]).sns.request_metadata(
            source_arn=s3_bucket_arn(verification_ctx.bucket_name),
            service_principal=ServicePrincipal.s3,
        )
        test_payload = self._get_test_payload(verification_ctx)
        try:
            sns_client.publish(
                TopicArn=target_arn,
                Message=json.dumps(test_payload),
                Subject="Amazon S3 Notification",
            )
        except ClientError as e:
            LOG.error(
                'Unable to send test notification for S3 bucket "%s" to SNS topic "%s"',
                verification_ctx.bucket_name,
                target_arn,
            )
            raise _create_invalid_argument_exc(
                "Unable to validate the following destination configurations",
                name=target_arn,
                value="Permissions on the destination topic do not allow S3 to publish notifications from this bucket",
            ) from e

    def notify(self, ctx: S3EventNotificationContext, config: TopicConfiguration):
        LOG.debug(
            "Task received by a worker for notification to %s for bucket %s, key %s, action %s",
            self.service_name,
            ctx.bucket_name,
            ctx.key_name,
            ctx.event_type,
        )
        event_payload = self._get_event_payload(ctx, config.get("Id"))
        message = json.dumps(event_payload)
        topic_arn = config["TopicArn"]

        arn_data = parse_arn(topic_arn)
        sns_client = connect_to(region_name=arn_data["region"]).sns.request_metadata(
            source_arn=s3_bucket_arn(ctx.bucket_name), service_principal=ServicePrincipal.s3
        )
        try:
            sns_client.publish(
                TopicArn=topic_arn,
                Message=message,
                Subject="Amazon S3 Notification",
            )
        except Exception:
            LOG.exception(
                'Unable to send notification for S3 bucket "%s" to SNS topic "%s"',
                ctx.bucket_name,
                topic_arn,
            )


class LambdaNotifier(BaseNotifier):
    service_name = "lambda"

    @staticmethod
    def _get_arn_value_and_name(
        lambda_configuration: LambdaFunctionConfiguration,
    ) -> Tuple[LambdaFunctionArn, str]:
        return lambda_configuration.get("LambdaFunctionArn", ""), "LambdaFunctionArn"

    def _verify_target(self, target_arn: str, verification_ctx: BucketVerificationContext) -> None:
        arn_data = parse_arn(arn=target_arn)
        lambda_client = connect_to(
            aws_access_key_id=arn_data["account"], region_name=arn_data["region"]
        ).lambda_
        try:
            lambda_client.get_function(FunctionName=target_arn)
        except ClientError:
            raise _create_invalid_argument_exc(
                "Unable to validate the following destination configurations",
                name=target_arn,
                value="The destination Lambda does not exist",
            )
        lambda_client = connect_to(region_name=arn_data["region"]).lambda_.request_metadata(
            source_arn=s3_bucket_arn(verification_ctx.bucket_name),
            service_principal=ServicePrincipal.s3,
        )
        try:
            lambda_client.invoke(FunctionName=target_arn, InvocationType=InvocationType.DryRun)
        except ClientError as e:
            raise _create_invalid_argument_exc(
                "Unable to validate the following destination configurations",
                name=f"{target_arn}, null",
                value=f"Not authorized to invoke function [{target_arn}]",
            ) from e

    def notify(self, ctx: S3EventNotificationContext, config: LambdaFunctionConfiguration):
        event_payload = self._get_event_payload(ctx, config.get("Id"))
        payload = json.dumps(event_payload)
        lambda_arn = config["LambdaFunctionArn"]

        arn_data = parse_arn(lambda_arn)

        lambda_client = connect_to(region_name=arn_data["region"]).lambda_.request_metadata(
            source_arn=s3_bucket_arn(ctx.bucket_name), service_principal=ServicePrincipal.s3
        )
        lambda_function_config = arns.lambda_function_name(lambda_arn)
        try:
            lambda_client.invoke(
                FunctionName=lambda_function_config,
                InvocationType="Event",
                Payload=payload,
            )
        except Exception:
            LOG.exception(
                'Unable to send notification for S3 bucket "%s" to Lambda function "%s".',
                ctx.bucket_name,
                lambda_function_config,
            )


class EventBridgeNotifier(BaseNotifier):
    @staticmethod
    def _get_event_payload(
        ctx: S3EventNotificationContext, config_id: NotificationId = None
    ) -> PutEventsRequestEntry:
        # see https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventBridge.html
        # see also https://docs.aws.amazon.com/AmazonS3/latest/userguide/ev-events.html
        entry: PutEventsRequestEntry = {
            "Source": "aws.s3",
            "Resources": [f"arn:aws:s3:::{ctx.bucket_name}"],
            "Time": ctx.event_time,
        }

        if ctx.xray:
            entry["TraceHeader"] = ctx.xray

        event_details = {
            "version": "0",
            "bucket": {"name": ctx.bucket_name},
            "object": {
                "key": ctx.key_name,
                "size": ctx.key_size,
                "etag": ctx.key_etag,
                "sequencer": "0062E99A88DC407460",
            },
            "request-id": ctx.request_id,
            "requester": "074255357339",
            "source-ip-address": "127.0.0.1",
            # TODO previously headers.get("X-Forwarded-For", "127.0.0.1").split(",")[0]
        }

        if "ObjectCreated" in ctx.event_type:
            entry["DetailType"] = "Object Created"
            event_type = ctx.event_type
            event_action = event_type[event_type.rindex(":") + 1 :]
            if event_action in ["Put", "Post", "Copy"]:
                event_type = f"{event_action}Object"
            # TODO: what about CompleteMultiformUpload??
            event_details["reason"] = event_type

        elif "ObjectRemoved" in ctx.event_type:
            entry["DetailType"] = "Object Deleted"
            event_details["reason"] = "DeleteObject"
            event_details[
                "deletion-type"
            ] = "Permanently Deleted"  # TODO: check with versioned bucket?
            event_details["object"].pop("etag")
            event_details["object"].pop("size")

        elif "ObjectTagging" in ctx.event_type:
            entry["DetailType"] = (
                "Object Tags Added" if "Put" in ctx.event_type else "Object Tags Deleted"
            )

        elif "ObjectAcl" in ctx.event_type:
            entry["DetailType"] = "Object ACL Updated"
            event_details["object"].pop("size")
            event_details["object"].pop("sequencer")

        elif "ObjectRestore" in ctx.event_type:
            entry["DetailType"] = (
                "Object Restore Initiated"
                if "Post" in ctx.event_type
                else "Object Restore Completed"
            )
            event_details["source-storage-class"] = ctx.key_storage_class
            event_details["object"].pop("sequencer", None)
            if ctx.event_type.endswith("Completed"):
                event_details["restore-expiry-time"] = timestamp_millis(ctx.key_expiry)
                event_details.pop("source-ip-address", None)
                # a bit hacky, it is to ensure the eventTime is a bit after the `Post` event, as its instant in LS
                # the best would be to delay the publishing of the event. We need at least 1s as it's the precision
                # of the event
                entry["Time"] = entry["Time"] + datetime.timedelta(seconds=1)

        entry["Detail"] = json.dumps(event_details)
        return entry

    @staticmethod
    def should_notify(ctx: S3EventNotificationContext, config: Dict) -> bool:
        # Events are always passed to EventBridge, you can route the event in EventBridge
        # See https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventBridge.html
        return True

    def validate_configuration_for_notifier(
        self,
        configurations: List[Dict],
        skip_destination_validation: bool,
        context: RequestContext,
        bucket_name: str,
    ):
        # There are no configuration for EventBridge, simply passing an empty dict will enable notifications
        return

    def _verify_target(self, target_arn: str, verification_ctx: BucketVerificationContext) -> None:
        # There are no target for EventBridge
        return

    def notify(self, ctx: S3EventNotificationContext, config: EventBridgeConfiguration):
        # does not require permissions
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/ev-permissions.html
        # the account_id should be the bucket owner
        # - account — The 12-digit AWS account ID of the bucket owner.
        events_client = connect_to(
            aws_access_key_id=ctx.bucket_account_id, region_name=ctx.bucket_location
        ).events
        entry = self._get_event_payload(ctx)
        try:
            events_client.put_events(Entries=[entry])
        except Exception:
            LOG.exception(
                'Unable to send notification for S3 bucket "%s" to EventBridge', ctx.bucket_name
            )


class NotificationDispatcher:
    notifiers = {
        "QueueConfigurations": SqsNotifier(),
        "TopicConfigurations": SnsNotifier(),
        "LambdaFunctionConfigurations": LambdaNotifier(),
        "EventBridgeConfiguration": EventBridgeNotifier(),
    }

    def __init__(self, num_thread: int = 3):
        self.executor = ThreadPoolExecutor(num_thread, thread_name_prefix="s3_ev")

    def shutdown(self):
        self.executor.shutdown(wait=False)

    def send_notifications(
        self, ctx: S3EventNotificationContext, notification_config: NotificationConfiguration
    ):
        for configuration_key, configurations in notification_config.items():
            notifier = self.notifiers[configuration_key]
            # there is not really a configuration for EventBridge, it is an empty dict
            configurations = (
                configurations if isinstance(configurations, list) else [configurations]
            )
            for config in configurations:
                if notifier.should_notify(ctx, config):  # we check before sending it to the thread
                    LOG.debug("Submitting task to the executor for notifier %s", notifier)
                    self.executor.submit(notifier.notify, ctx, config)

    def verify_configuration(
        self,
        notification_configurations: NotificationConfiguration,
        skip_destination_validation,
        context: RequestContext,
        bucket_name: str,
    ):
        for notifier_type, notification_configuration in notification_configurations.items():
            self.notifiers[notifier_type].validate_configuration_for_notifier(
                notification_configuration, skip_destination_validation, context, bucket_name
            )
