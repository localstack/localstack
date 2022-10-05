from localstack.services.awslambda.invocation.lambda_models import (
    CodeSigningConfig,
    EventSourceMapping,
    Function,
    Layer,
)
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class LambdaStore(BaseStore):
    functions: dict[str, Function] = LocalAttribute(default=dict)
    event_source_mappings: dict[str, EventSourceMapping] = LocalAttribute(default=dict)
    code_signing_configs: dict[str, CodeSigningConfig] = LocalAttribute(default=dict)
    layers: dict[str, Layer] = LocalAttribute(default=dict)
    tags: dict[str, dict[str, str]] = LocalAttribute(default=dict)


lambda_stores = AccountRegionBundle[LambdaStore]("lambda", LambdaStore)
