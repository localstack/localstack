from typing import Dict

from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class EventsStore(BaseStore):
    # maps rule name to job_id
    rule_scheduled_jobs: Dict[str, str] = LocalAttribute(default=dict)


events_stores = AccountRegionBundle("events", EventsStore)
