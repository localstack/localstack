from localstack.services.awslambda.invocation.lambda_models import (
    AccountSettings,
    CodeSigningConfig,
    EventSourceMapping,
    Function,
    Layer,
)
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class LambdaStore(BaseStore):
    # maps function names to the respective Function
    functions: dict[str, Function] = LocalAttribute(default=dict)

    # maps EventSourceMapping UUIDs to the respective EventSourceMapping
    event_source_mappings: dict[str, EventSourceMapping] = LocalAttribute(default=dict)

    # maps CodeSigningConfig ARNs to the respective CodeSigningConfig
    code_signing_configs: dict[str, CodeSigningConfig] = LocalAttribute(default=dict)

    # maps layer names to Layers
    layers: dict[str, Layer] = LocalAttribute(default=dict)

    # region-specific account settings/limits
    settings: AccountSettings = LocalAttribute(default=AccountSettings)


lambda_stores = AccountRegionBundle[LambdaStore]("lambda", LambdaStore)
