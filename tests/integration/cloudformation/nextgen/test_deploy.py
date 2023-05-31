from typing import TypeVar

import pytest

from localstack.aws.api.lambda_ import Runtime
from localstack.services.awslambda.resource_providers.function import LambdaFunctionAllProperties
from localstack.services.opensearch.resource_providers.domain import OpenSearchDomainAllProperties
from localstack.services.ssm.resource_providers.parameter import SSMParameterAllProperties
from localstack.utils.strings import short_uid

Properties = TypeVar("Properties")


@pytest.mark.parametrize(
    "type_name,props",
    [
        # TODO: Installation of opensearch failed.
        (
            "AWS::OpenSearchService::Domain",
            OpenSearchDomainAllProperties(DomainName=f"domain-{short_uid()}"),
        ),
        (
            "AWS::SSM::Parameter",
            SSMParameterAllProperties(Type="String", Value=f"value-{short_uid()}"),
        ),
        (
            "AWS::Lambda::Function",
            LambdaFunctionAllProperties(
                FunctionName=f"cfn-lambda-function-{short_uid()}",
                # TODO: How to set up a ZIP file dependency in these parameters here?
                # TODO: typing, would be nice if this works like in ASF
                Code={
                    "ZipFile": "exports.handler = function(event, context){\nconsole.log('SUCCESS');"
                },
                # Code={"ZipFile": create_zip_file_with_lambda},
                # TODO: How to setup a dependency resource here?
                Role="arn:aws:iam::000000000000:role/lambda-role",
                # Role=LambdaRole.Arn,
                Runtime=Runtime.nodejs18_x,
            ),
        )
        # TODO: Add your resource definitions here!
    ],
    # ids=["lambda-function"],
    ids=["opensearch-domain", "ssm-parameter", "lambda-function"],
)
# @pytest.mark.skip(reason="Example")
def test_roundtrip(type_name, props, perform_cfn_operation):
    # deploy
    event = perform_cfn_operation(
        logical_resource_id="MyResource",
        resource_type=type_name,
        action="Add",
        resource_props=props,
    )

    # delete
    perform_cfn_operation(
        logical_resource_id="MyResource",
        resource_type=type_name,
        action="Remove",
        resource_props=event.resource_model,
    )
