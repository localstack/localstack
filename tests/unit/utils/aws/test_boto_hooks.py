import boto3
import pytest
from botocore.hooks import EventAliaser, HierarchicalEmitter

from localstack.utils.aws.boto_hooks import register_parameter_to_header_hooks


def get_handlers_for_event(event_emitter: EventAliaser, event_name: str):
    # Extract all event hooks for a given operation/event-name
    emitter: HierarchicalEmitter = event_emitter._emitter
    return emitter._handlers.prefix_search(event_name)


@pytest.fixture
def s3_client():
    return boto3.client("s3")


@pytest.fixture
def dynamodb_client():
    return boto3.client("dynamodb")


@pytest.fixture
def handler_counter():
    class HandlerCounter:
        def __init__(self):
            self.initial_counts = {}

        def count_before(self, client, event_names):
            for event_name in event_names:
                handlers = get_handlers_for_event(client.meta.events, event_name)
                self.initial_counts[event_name] = len(handlers)
            return self

        def assert_added(self, client, event_name, count=1):
            current_handlers = get_handlers_for_event(client.meta.events, event_name)
            initial_count = self.initial_counts.get(event_name, 0)
            assert len(current_handlers) == initial_count + count, (
                f"Expected {count} new handler(s) for {event_name}, but got {len(current_handlers) - initial_count}"
            )

        def assert_unchanged(self, client, event_name):
            self.assert_added(client, event_name, count=0)

    return HandlerCounter()


def test_register_single_hook(s3_client, handler_counter):
    counter = handler_counter.count_before(
        s3_client,
        [
            "provide-client-params.s3.GetObject",
            "before-call.s3.GetObject",
            "before-call.s3.PutObject",
        ],
    )

    with register_parameter_to_header_hooks(s3_client) as register_hook:
        register_hook("GetObject", "my-param", "X-My-Header")

    counter.assert_added(s3_client, "provide-client-params.s3.GetObject")
    counter.assert_added(s3_client, "before-call.s3.GetObject")
    counter.assert_unchanged(s3_client, "before-call.s3.PutObject")


def test_register_multiple_hooks(s3_client, handler_counter):
    counter = handler_counter.count_before(
        s3_client,
        [
            "provide-client-params.s3.GetObject",
            "before-call.s3.GetObject",
            "provide-client-params.s3.PutObject",
            "before-call.s3.PutObject",
        ],
    )

    with register_parameter_to_header_hooks(s3_client) as register_hook:
        register_hook("GetObject", "my-param", "X-My-Header")
        register_hook("PutObject", "other-param", "X-Other-Header")

    counter.assert_added(s3_client, "provide-client-params.s3.GetObject")
    counter.assert_added(s3_client, "before-call.s3.GetObject")
    counter.assert_added(s3_client, "provide-client-params.s3.PutObject")
    counter.assert_added(s3_client, "before-call.s3.PutObject")


def test_register_sqs_with_validators(handler_counter):
    sqs_client = boto3.client("sqs")

    counter = handler_counter.count_before(
        sqs_client, ["provide-client-params.sqs.SendMessage", "before-call.sqs.SendMessage"]
    )

    with register_parameter_to_header_hooks(sqs_client) as register_hook:
        register_hook(
            "SendMessage",
            "priority",
            "X-Priority",
            validators=[lambda x: x > 10],
        )

    counter.assert_added(sqs_client, "provide-client-params.sqs.SendMessage")
    counter.assert_added(sqs_client, "before-call.sqs.SendMessage")


def test_register_with_validators_and_transformers(s3_client, handler_counter):
    def is_string(value):
        return isinstance(value, str)

    def to_uppercase(value):
        return value.upper() if value else value

    counter = handler_counter.count_before(
        s3_client, ["provide-client-params.s3.GetObject", "before-call.s3.GetObject"]
    )

    with register_parameter_to_header_hooks(s3_client) as register_hook:
        register_hook(
            "GetObject",
            "my-param",
            "X-My-Header",
            validators=[is_string],
            transformers=[to_uppercase],
        )

    counter.assert_added(s3_client, "provide-client-params.s3.GetObject")
    counter.assert_added(s3_client, "before-call.s3.GetObject")


def test_register_error_handling(s3_client, handler_counter):
    counter = handler_counter.count_before(
        s3_client, ["provide-client-params.s3.GetObject", "before-call.s3.GetObject"]
    )

    try:
        with register_parameter_to_header_hooks(s3_client) as register_hook:
            register_hook("GetObject", "my-param", "X-My-Header")
            raise ValueError("Test exception")
    except ValueError:
        pass

    counter.assert_unchanged(s3_client, "provide-client-params.s3.GetObject")
    counter.assert_unchanged(s3_client, "before-call.s3.GetObject")


def test_register_invalid_operation(s3_client):
    with pytest.raises(ValueError):
        with register_parameter_to_header_hooks(s3_client) as register_hook:
            register_hook("NonExistentOperation", "my-param", "X-My-Header")


def test_multiple_clients(s3_client, dynamodb_client, handler_counter):
    counter = handler_counter.count_before(
        s3_client, ["provide-client-params.s3.GetObject", "before-call.s3.GetObject"]
    )
    counter.count_before(
        dynamodb_client, ["provide-client-params.dynamodb.Query", "before-call.dynamodb.Query"]
    )

    with register_parameter_to_header_hooks(s3_client) as register_s3:
        register_s3("GetObject", "trace-id", "X-Trace-ID")

    with register_parameter_to_header_hooks(dynamodb_client) as register_ddb:
        register_ddb("Query", "trace-id", "X-Trace-ID")

    counter.assert_added(s3_client, "provide-client-params.s3.GetObject")
    counter.assert_added(s3_client, "before-call.s3.GetObject")
    counter.assert_added(dynamodb_client, "provide-client-params.dynamodb.Query")
    counter.assert_added(dynamodb_client, "before-call.dynamodb.Query")
