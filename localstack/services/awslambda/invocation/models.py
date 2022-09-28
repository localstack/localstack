from localstack.services.awslambda.invocation.lambda_models import (
    CodeSigningConfig,
    EventSourceMapping,
    Function,
    Layer,
)
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)


class LambdaStore(BaseStore):
    functions: dict[str, Function] = LocalAttribute(default=dict)
    event_source_mappings: dict[str, EventSourceMapping] = LocalAttribute(default=dict)
    code_signing_configs: dict[str, CodeSigningConfig] = LocalAttribute(default=dict)
    layers: dict[str, Layer] = LocalAttribute(default=dict)
    TAGS: dict[str, dict[str, str]] = CrossRegionAttribute(default=dict)


lambda_stores = AccountRegionBundle[LambdaStore]("lambda", LambdaStore)
