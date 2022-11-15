import os

import pytest


@pytest.mark.skip(reason="Not implemented")
@pytest.mark.aws_validated
def test_drift_detection_on_lambda(deploy_cfn_template, cfn_client, lambda_client, snapshot):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../templates/lambda_simple.yml")
    )

    lambda_client.update_function_configuration(
        FunctionName=stack.outputs["LambdaName"],
        Runtime="python3.8",
        Description="different description",
        Environment={"Variables": {"ENDPOINT_URL": "localhost.localstack.cloud"}},
    )

    drift_detection = cfn_client.detect_stack_resource_drift(
        StackName=stack.stack_name, LogicalResourceId="Function"
    )

    snapshot.match("drift_detection", drift_detection)
