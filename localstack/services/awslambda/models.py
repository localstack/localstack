from typing import Dict, List

from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute
from localstack.utils.aws.aws_models import CodeSigningConfig, LambdaFunction


class LambdaStore(BaseStore):
    # map ARN strings to lambda function objects
    lambdas: Dict[str, LambdaFunction] = LocalAttribute(default=dict)

    # map ARN strings to CodeSigningConfig object
    code_signing_configs: Dict[str, CodeSigningConfig] = LocalAttribute(default=dict)

    # list of event source mappings for the API
    event_source_mappings: List[Dict] = LocalAttribute(default=list)

    # map ARN strings to url configs
    url_configs: Dict[str, Dict] = LocalAttribute(default=dict)


lambda_stores = AccountRegionBundle("lambda", LambdaStore)
