import time
from unittest.mock import Mock

from localstack import config
from localstack.services.lambda_.event_source_mapping.pollers import sqs_poller as sqs_poller_module
from localstack.services.lambda_.event_source_mapping.pollers.sqs_poller import SqsPoller


def _create_source_client(receive_message_responses: list[dict]) -> Mock:
    source_client = Mock()
    source_client.meta.events.register = Mock()
    source_client.receive_message.side_effect = receive_message_responses
    source_client.get_queue_attributes.return_value = {"Attributes": {"FifoQueue": "false"}}
    return source_client


def _create_poller(monkeypatch, source_client: Mock) -> SqsPoller:
    monkeypatch.setattr(
        sqs_poller_module,
        "get_queue_url",
        lambda *_args, **_kwargs: (
            "http://sqs.us-east-1.localhost.localstack.cloud/000000000000/test"
        ),
    )
    source_parameters = {
        "FilterCriteria": {"Filters": []},
        "SqsQueueParameters": {"BatchSize": 10, "MaximumBatchingWindowInSeconds": 0},
    }
    processor = Mock()
    processor.process_events_batch = Mock()
    processor.generate_event_failure_context = Mock(return_value={})
    poller = SqsPoller(
        source_arn="arn:aws:sqs:us-east-1:000000000000:test",
        source_parameters=source_parameters,
        source_client=source_client,
        processor=processor,
    )
    poller.__dict__["is_fifo_queue"] = False
    return poller


def _one_message() -> dict:
    return {"MessageId": "msg-1", "ReceiptHandle": "rh-1"}


def test_sqs_poller_parallelism_disabled_processes_inline(monkeypatch):
    monkeypatch.setattr(config, "LAMBDA_SQS_EVENT_SOURCE_MAPPING_PARALLELISM", False)
    source_client = _create_source_client([{"Messages": [_one_message()]}])
    poller = _create_poller(monkeypatch, source_client)

    handle_messages = Mock()
    monkeypatch.setattr(poller, "handle_messages", handle_messages)
    poller.poll_events()

    assert not poller._inflight_futures
    assert handle_messages.call_count == 1
    assert source_client.receive_message.call_count == 1
    poller.close()


def test_sqs_poller_parallelism_enabled_submits_async(monkeypatch):
    monkeypatch.setattr(config, "LAMBDA_SQS_EVENT_SOURCE_MAPPING_PARALLELISM", True)
    source_client = _create_source_client([{"Messages": [_one_message()]}, {"Messages": []}])
    poller = _create_poller(monkeypatch, source_client)

    monkeypatch.setattr(poller, "handle_messages", lambda _messages: time.sleep(0.25))
    poller.poll_events()

    assert len(poller._inflight_futures) == 1
    assert source_client.receive_message.call_count == 2
    poller.close()
