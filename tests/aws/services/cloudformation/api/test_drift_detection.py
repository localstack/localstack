import os

import pytest

from localstack.testing.pytest import markers


@pytest.mark.skip(reason="Not implemented")
@markers.aws.validated
def test_drift_detection_on_lambda(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/lambda_simple.yml"
        )
    )

    aws_client.lambda_.update_function_configuration(
        FunctionName=stack.outputs["LambdaName"],
        Runtime="python3.8",
        Description="different description",
        Environment={"Variables": {"ENDPOINT_URL": "localhost.localstack.cloud"}},
    )

    drift_detection = aws_client.cloudformation.detect_stack_resource_drift(
        StackName=stack.stack_name, LogicalResourceId="Function"
    )

    snapshot.match("drift_detection", drift_detection)
