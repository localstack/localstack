from typing import Dict, List

from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute
from localstack.utils.aws.aws_models import CodeSigningConfig, LambdaFunction


# This store is for the non-ASF Lambda provider and can be distinguished by the `Aws` prefix
class AwsLambdaStore(BaseStore):
    # map ARN strings to lambda function objects
    lambdas: Dict[str, LambdaFunction] = LocalAttribute(default=dict)

    # map ARN strings to CodeSigningConfig object
    code_signing_configs: Dict[str, CodeSigningConfig] = LocalAttribute(default=dict)

    # list of event source mappings for the API
    event_source_mappings: List[Dict] = LocalAttribute(default=list)

    # map ARN strings to url configs
    url_configs: Dict[str, Dict] = LocalAttribute(default=dict)

    # maps Lambda ARNs to layers ARNs configured for that Lambda (pro)
    layers: Dict[str, str] = LocalAttribute(default=dict)


awslambda_stores = AccountRegionBundle[AwsLambdaStore]("lambda", AwsLambdaStore)
