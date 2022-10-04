from typing import Dict, List

from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class SnsStore(BaseStore):
    # maps topic ARN to list of subscriptions
    sns_subscriptions: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # maps subscription ARN to subscription status
    subscription_status: Dict[str, Dict] = LocalAttribute(default=dict)

    # maps topic ARN to list of tags
    sns_tags: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # cache of topic ARN to platform endpoint messages (used primarily for testing)
    platform_endpoint_messages: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # list of sent SMS messages - TODO: expose via internal API
    sms_messages: List[Dict] = LocalAttribute(default=list)


sns_stores = AccountRegionBundle("sns", SnsStore)
