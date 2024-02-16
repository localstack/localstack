from concurrent.futures.thread import ThreadPoolExecutor
from typing import Dict

import logging

from localstack.utils.aws.message_forwarding import send_event_to_target as send_event_to_target_
from localstack.utils.common import truncate

LOG = logging.getLogger(__name__)


def send_event_to_target(
    target_arn: str,
    event: Dict,
    target_attributes: Dict = None,
    asynchronous: bool = True,
    target: Dict = None,
    role: str = None,
    source_arn: str = None,
    source_service: str = None,
):
    try:
        send_event_to_target_(
            target_arn,
            event,
            target_attributes=target_attributes,
            asynchronous=asynchronous,
            target=target,
            role=role,
            source_arn=source_arn,
            source_service=source_service
        )
    except Exception as e:
        LOG.info(f"Unable to send event notification {truncate(event)} to target {target}: {e}")


class EventTargetPublisher:
    def __init__(self, thread_count: int = 10):
        self.executor = ThreadPoolExecutor(thread_count, thread_name_prefix="eb_targets")

    def shutdown(self):
        self.executor.shutdown(wait=False)

    def send_event_to_target(
            self,
            target_arn: str,
            event: Dict,
            target_attributes: Dict = None,
            asynchronous: bool = True,
            target: Dict = None,
            role: str = None,
            source_arn: str = None,
            source_service: str = None,
    ):
        self.executor.submit(send_event_to_target, target_arn, event, target_attributes=target_attributes,
                              asynchronous=asynchronous, target=target, role=role, source_arn=source_arn,
                              source_service=source_service)
