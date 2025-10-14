from typing import TypedDict

from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class ServerInstance(TypedDict, total=False):
    account_id: str
    region_name: str
    server_id: str


class TransferStore(BaseStore):
    servers: dict[str, ServerInstance] = LocalAttribute(default=dict)


transfer_stores = AccountRegionBundle("transfer", TransferStore)
