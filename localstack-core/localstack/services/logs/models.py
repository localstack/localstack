from moto.logs.models import LogsBackend as MotoLogsBackend
from moto.logs.models import logs_backends as moto_logs_backend

from localstack.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute


def get_moto_logs_backend(account_id: str, region_name: str) -> MotoLogsBackend:
    return moto_logs_backend[account_id][region_name]


class LogsStore(BaseStore):
    # maps resource ARN to tags
    TAGS: dict[str, dict[str, str]] = CrossRegionAttribute(default=dict)


logs_stores = AccountRegionBundle("logs", LogsStore)
