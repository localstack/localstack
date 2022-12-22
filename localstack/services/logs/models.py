from typing import Dict

from moto.logs.models import LogsBackend as MotoLogsBackend
from moto.logs.models import logs_backends as moto_logs_backend

from localstack.constants import DEFAULT_AWS_ACCOUNT_ID
from localstack.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute
from localstack.utils.aws import aws_stack


def get_moto_logs_backend(account_id: str = None, region_name: str = None) -> MotoLogsBackend:
    account_id = account_id or DEFAULT_AWS_ACCOUNT_ID
    region_name = region_name or aws_stack.get_region()

    return moto_logs_backend[account_id][region_name]


class LogsStore(BaseStore):

    # maps resource ARN to tags
    TAGS: Dict[str, Dict[str, str]] = CrossRegionAttribute(default=dict)


logs_stores = AccountRegionBundle("logs", LogsStore)
