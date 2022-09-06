import time
from typing import Dict

from localstack.services.sqs.constants import RECENTLY_DELETED_TIMEOUT
from localstack.services.sqs.provider import SqsQueue
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class SqsStore(BaseStore):
    queues: Dict[str, SqsQueue] = LocalAttribute(default=dict)

    deleted: Dict[str, float] = LocalAttribute(default=dict)

    def expire_deleted(self):
        for k in list(self.deleted.keys()):
            if self.deleted[k] <= (time.time() - RECENTLY_DELETED_TIMEOUT):
                del self.deleted[k]


sqs_stores = AccountRegionBundle("sqs", SqsStore)
