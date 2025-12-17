from moto.logs.models import LogsBackend as MotoLogsBackend
from moto.logs.models import logs_backends as moto_logs_backend

from localstack.aws.api.logs import LogGroup, LogGroupName, LogStream, LogStreamName
from localstack.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute


def get_moto_logs_backend(account_id: str, region_name: str) -> MotoLogsBackend:
    return moto_logs_backend[account_id][region_name]


class LogsStore(BaseStore):
    # maps resource ARN to tags
    TAGS: dict[str, dict[str, str]] = CrossRegionAttribute(default=dict)
    # maps log group name to log group
    log_groups: dict[LogGroupName, LogGroup] = CrossRegionAttribute(default=dict)
    # maps log group name to a dict of log stream name to log stream
    log_streams: dict[LogGroupName, dict[LogStreamName, LogStream]] = CrossRegionAttribute(
        default=dict
    )


logs_stores = AccountRegionBundle("logs", LogsStore)
