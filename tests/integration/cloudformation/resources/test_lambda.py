import json
import os

import pytest

from localstack.testing.snapshots.transformer import SortingTransformer
from localstack.utils.common import short_uid, to_str
from localstack.utils.http import safe_requests
from localstack.utils.sync import retry
from localstack.utils.testutil import get_lambda_log_events


def test_lambda_autogenerated_name(cfn_client, lambda_client, deploy_cfn_template):
    lambda_functional_id = f"MyFn{short_uid()}"

    stack_created = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/cfn_lambda_noname.yaml"
        ),
        template_mapping={"lambda_functional_id": lambda_functional_id},
    )

    description = cfn_client.describe_stack_resource(
        StackName=stack_created.stack_name, LogicalResourceId=lambda_functional_id
    )
    assert description["StackResourceDetail"]["LogicalResourceId"] == lambda_functional_id


@pytest.mark.parametrize("return_value", ["hello world", "hello globe"])
def test_update_lambda_inline_code(cfn_client, lambda_client, return_value, deploy_cfn_template):
    function_name = f"test-fn-{short_uid()}"

    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/lambda_inline_code.yaml"
        ),
        parameters={"FunctionName": function_name, "Arch": "x86_64", "ReturnValue": return_value},
    )

    rs = lambda_client.get_function(FunctionName=function_name)
    assert function_name == rs["Configuration"]["FunctionName"]
    assert "x86_64" in rs["Configuration"]["Architectures"]
    result = lambda_client.invoke(FunctionName=function_name)
    result = to_str(result["Payload"].read())
    assert result.strip('" \n') == return_value


@pytest.mark.aws_validated
def test_lambda_w_dynamodb_event_filter(
    cfn_client, dynamodb_client, logs_client, deploy_cfn_template
):
    function_name = f"test-fn-{short_uid()}"
    table_name = f"ddb-tbl-{short_uid()}"
    item_to_put = {"id": {"S": "test123"}, "id2": {"S": "test42"}}
    item_to_put2 = {"id": {"S": "test123"}, "id2": {"S": "test67"}}

    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/lambda_dynamodb_filtering.yaml"
        ),
        parameters={
            "FunctionName": function_name,
            "TableName": table_name,
            "Filter": '{"eventName": ["MODIFY"]}',
        },
    )

    dynamodb_client.put_item(TableName=table_name, Item=item_to_put)
    dynamodb_client.put_item(TableName=table_name, Item=item_to_put2)

    def _assert_single_lambda_call():
        events = get_lambda_log_events(function_name, logs_client=logs_client)
        assert len(events) == 1
        msg = events[0]
        if not isinstance(msg, str):
            msg = json.dumps(msg)
        assert "MODIFY" in msg and "INSERT" not in msg

    retry(_assert_single_lambda_call, retries=30)


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(
    paths=[
        "$..Metadata",
        "$..DriftInformation",
        "$..Type",
        "$..Message",
        "$..access-control-allow-headers",
        "$..access-control-allow-methods",
        "$..access-control-allow-origin",
        "$..access-control-expose-headers",
        "$..server",
        "$..content-length",
    ]
)
def test_cfn_function_url(deploy_cfn_template, cfn_client, lambda_client, snapshot):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.lambda_api())

    deploy = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../templates/lambda_url.yaml")
    )

    url_logical_resource_id = "UrlD4FAABD0"
    snapshot.add_transformer(
        snapshot.transform.regex(url_logical_resource_id, "<url_logical_resource_id>")
    )
    snapshot.add_transformer(
        snapshot.transform.key_value(
            "FunctionUrl",
        )
    )
    snapshot.add_transformer(
        snapshot.transform.key_value("x-amzn-trace-id", reference_replacement=False)
    )
    snapshot.add_transformer(snapshot.transform.key_value("date", reference_replacement=False))

    url_resource = cfn_client.describe_stack_resource(
        StackName=deploy.stack_name, LogicalResourceId=url_logical_resource_id
    )
    snapshot.match("url_resource", url_resource)

    url_config = lambda_client.get_function_url_config(FunctionName=deploy.outputs["LambdaName"])
    snapshot.match("url_config", url_config)

    with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
        lambda_client.get_function_url_config(
            FunctionName=deploy.outputs["LambdaName"], Qualifier="unknownalias"
        )

    snapshot.match("exception_url_config_nonexistent_version", e.value.response)

    url_config_arn = lambda_client.get_function_url_config(FunctionName=deploy.outputs["LambdaArn"])
    snapshot.match("url_config_arn", url_config_arn)

    response = safe_requests.get(deploy.outputs["LambdaUrl"])
    assert response.ok
    assert response.json() == {"hello": "world"}

    lowered_headers = {k.lower(): v for k, v in response.headers.items()}
    snapshot.match("response_headers", lowered_headers)


@pytest.mark.skip_snapshot_verify(
    paths=["$..StackResources..PhysicalResourceId", "$..StackResources..StackId"]
)
def test_lambda_alias(deploy_cfn_template, cfn_client, lambda_client, snapshot):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.lambda_api())
    snapshot.add_transformer(snapshot.transform.key_value("AliasArn", "alias-arn"))
    snapshot.add_transformer(snapshot.transform.key_value("Name", "alias-name"))
    snapshot.add_transformer(snapshot.transform.key_value("FunctionVersion", "function-version"))
    snapshot.add_transformer(SortingTransformer("StackResources", lambda x: x["LogicalResourceId"]))

    lambda_name = f"function{short_uid()}"
    alias_name = f"alias{short_uid()}"

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/cfn_lambda_alias.yml"
        ),
        parameters={"FunctionName": lambda_name, "AliasName": alias_name},
    )

    description = cfn_client.describe_stack_resources(StackName=stack.stack_name)
    snapshot.match("stack_resource_descriptions", description)

    alias = lambda_client.get_alias(FunctionName=lambda_name, Name=alias_name)
    snapshot.match("Alias", alias)


def test_lambda_code_signing_config(
    deploy_cfn_template, cfn_client, lambda_client, snapshot, account_id
):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.lambda_api())
    snapshot.add_transformer(SortingTransformer("StackResources", lambda x: x["LogicalResourceId"]))

    signer_arn = (
        f"arn:aws:signer:{lambda_client.meta.region_name}:{account_id}:/signing-profiles/test"
    )

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/cfn_lambda_code_signing_config.yml"
        ),
        parameters={"SignerArn": signer_arn},
    )

    description = cfn_client.describe_stack_resources(StackName=stack.stack_name)
    snapshot.match("stack_resource_descriptions", description)

    snapshot.match(
        "config", lambda_client.get_code_signing_config(CodeSigningConfigArn=stack.outputs["Arn"])
    )
