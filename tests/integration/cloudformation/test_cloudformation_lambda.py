import json
import os

import jinja2
import pytest

from localstack.testing.aws.cloudformation_utils import load_template_file
from localstack.utils.common import short_uid, to_str
from localstack.utils.generic.wait_utils import wait_until
from localstack.utils.http import safe_requests
from localstack.utils.sync import retry
from localstack.utils.testutil import get_lambda_log_events


# TODO: refactor file and remove this compatibility fn
def load_template_raw(file_name: str):
    return load_template_file(os.path.join(os.path.dirname(__file__), "../templates", file_name))


def test_lambda_autogenerated_name(
    cfn_client,
    lambda_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    lambda_functional_id = f"MyFn{short_uid()}"
    template_rendered = jinja2.Template(load_template_raw("cfn_lambda_noname.yaml")).render(
        lambda_functional_id=lambda_functional_id
    )

    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template_rendered,
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]

    try:
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        wait_until(is_stack_created(stack_id))

        outputs = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]
        assert len(outputs) == 1
        assert lambda_functional_id in outputs[0]["OutputValue"]

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])


def test_update_lambda_inline_code(
    cfn_client, lambda_client, is_stack_created, is_stack_updated, cleanup_stacks
):
    stack_name = f"stack-{short_uid()}"
    function_name = f"test-fn-{short_uid()}"

    try:
        template_1 = jinja2.Template(load_template_raw("lambda_inline_code.yaml")).render(
            lambda_return_value="hello world",
            arch="x86_64",
            function_name=function_name,
        )
        response = cfn_client.create_stack(
            StackName=stack_name, TemplateBody=template_1, Capabilities=["CAPABILITY_IAM"]
        )
        stack_id = response["StackId"]
        assert stack_id
        wait_until(is_stack_created(stack_id))

        rs = lambda_client.get_function(FunctionName=function_name)
        assert function_name == rs["Configuration"]["FunctionName"]
        assert "x86_64" in rs["Configuration"]["Architectures"]
        result = lambda_client.invoke(FunctionName=function_name)
        result = to_str(result["Payload"].read())
        assert result.strip('" \n') == "hello world"

        template_2 = jinja2.Template(load_template_raw("lambda_inline_code.yaml")).render(
            lambda_return_value="hello globe", arch="arm64", function_name=function_name
        )
        cfn_client.update_stack(
            StackName=stack_name, TemplateBody=template_2, Capabilities=["CAPABILITY_IAM"]
        )
        wait_until(is_stack_updated(stack_id))

        rs = lambda_client.get_function(FunctionName=function_name)
        assert function_name == rs["Configuration"]["FunctionName"]
        assert "arm64" in rs["Configuration"]["Architectures"]
        result = lambda_client.invoke(FunctionName=function_name)
        result = to_str(result["Payload"].read())
        assert result.strip('" \n') == "hello globe"
    finally:
        # cleanup
        cleanup_stacks([stack_name])


@pytest.mark.aws_validated
def test_lambda_w_dynamodb_event_filter(
    cfn_client, dynamodb_client, is_stack_created, cleanup_stacks, logs_client
):
    stack_name = f"stack-{short_uid()}"
    function_name = f"test-fn-{short_uid()}"
    table_name = f"ddb-tbl-{short_uid()}"
    item_to_put = {"id": {"S": "test123"}, "id2": {"S": "test42"}}
    item_to_put2 = {"id": {"S": "test123"}, "id2": {"S": "test67"}}

    try:
        template_1 = jinja2.Template(load_template_raw("lambda_dynamodb_filtering.yaml")).render(
            event_filter='{"eventName": ["MODIFY"]}',
            table_name=table_name,
            function_name=function_name,
        )

        response = cfn_client.create_stack(
            StackName=stack_name,
            TemplateBody=template_1,
            Capabilities=["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"],
        )
        stack_id = response["StackId"]
        assert stack_id
        wait_until(is_stack_created(stack_id))

        # put item the first time: INSERT
        dynamodb_client.put_item(TableName=table_name, Item=item_to_put)

        def _assert_single_lambda_call():
            events = get_lambda_log_events(function_name, logs_client=logs_client)
            assert len(events) == 1
            msg = events[0]
            # msg is either string or a result of json.loads
            if not isinstance(msg, str):
                msg = json.dumps(msg)
            assert "MODIFY" in msg and "INSERT" not in msg

        # put item the second time: MODIFY and lambda should be called
        dynamodb_client.put_item(TableName=table_name, Item=item_to_put2)
        retry(_assert_single_lambda_call, retries=30)

    finally:
        # cleanup
        cleanup_stacks([stack_name])


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
    ]
)
def test_cfn_function_url(deploy_cfn_template, cfn_client, lambda_client, snapshot):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.lambda_api())

    deploy = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../templates/lambda_url.yaml")
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
