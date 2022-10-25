import json
import os

import pytest

from localstack.testing.snapshots.transformer import SortingTransformer
from localstack.utils.common import short_uid, to_str
from localstack.utils.http import safe_requests
from localstack.utils.sync import retry, wait_until
from localstack.utils.testutil import get_lambda_log_events


# TODO: test name doesn't seem to correspond to actual test logic
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


# TODO: what's the purpose of this test?
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


class TestCfnLambdaIntegrations:
    @pytest.mark.aws_validated
    def test_cfn_lambda_permissions(
        self,
        deploy_cfn_template,
        lambda_client,
        cfn_client,
        sns_client,
        logs_client,
        iam_client,
        snapshot,
    ):
        """
        * Lambda Function
        * Lambda Permission
        * SNS Topic
        """

        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.sns_api())
        snapshot.add_transformer(
            SortingTransformer("StackResources", lambda sr: sr["LogicalResourceId"])
        )
        snapshot.add_transformer(snapshot.transform.key_value("CodeSha256"))
        snapshot.add_transformer(
            snapshot.transform.key_value("Sid"), priority=-1
        )  # TODO: need a better snapshot construct here
        # Sid format: e.g. `<logical resource id>-6JTUCQQ17UXN`

        deployment = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/cfn_lambda_sns_permissions.yaml"
            ),
            max_wait=240,
        )

        # verify by checking APIs

        stack_resources = cfn_client.describe_stack_resources(StackName=deployment.stack_id)
        snapshot.match("stack_resources", stack_resources)

        fn_name = deployment.outputs["FunctionName"]
        # topic_name = deployment.outputs["TopicName"]
        topic_arn = deployment.outputs["TopicArn"]

        get_function_result = lambda_client.get_function(FunctionName=fn_name)
        get_topic_attributes_result = sns_client.get_topic_attributes(TopicArn=topic_arn)
        get_policy_result = lambda_client.get_policy(FunctionName=fn_name)
        snapshot.match("get_function_result", get_function_result)
        snapshot.match("get_topic_attributes_result", get_topic_attributes_result)
        snapshot.match("get_policy_result", get_policy_result)

        # check that lambda is invoked

        msg = f"msg-verification-{short_uid()}"
        sns_client.publish(Message=msg, TopicArn=topic_arn)

        def wait_logs():
            log_events = logs_client.filter_log_events(logGroupName=f"/aws/lambda/{fn_name}")[
                "events"
            ]
            return any([msg in e["message"] for e in log_events])

        assert wait_until(wait_logs)

    @pytest.mark.aws_validated
    def test_cfn_lambda_sqs_source(
        self,
        deploy_cfn_template,
        cfn_client,
        lambda_client,
        sqs_client,
        logs_client,
        iam_client,
        snapshot,
    ):
        """
        Resources:
        * Lambda Function
        * SQS Queue
        * EventSourceMapping
        * IAM Roles/Policies (e.g. sqs:ReceiveMessage for lambda service to poll SQS)
        """

        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.sns_api())
        snapshot.add_transformer(
            SortingTransformer("StackResources", lambda sr: sr["LogicalResourceId"])
        )
        snapshot.add_transformer(snapshot.transform.key_value("CodeSha256"))
        snapshot.add_transformer(snapshot.transform.key_value("RoleId"))

        deployment = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/cfn_lambda_sqs_source.yaml"
            ),
            max_wait=240,
        )
        fn_name = deployment.outputs["FunctionName"]
        queue_url = deployment.outputs["QueueUrl"]
        esm_id = deployment.outputs["ESMId"]

        stack_resources = cfn_client.describe_stack_resources(StackName=deployment.stack_id)

        # IAM::Policy seems to have a pretty weird physical resource ID (e.g. stack-fnSe-3OZPF82JL41D)
        iam_policy_resource = cfn_client.describe_stack_resource(
            StackName=deployment.stack_id, LogicalResourceId="fnServiceRoleDefaultPolicy0ED5D3E5"
        )
        snapshot.add_transformer(
            snapshot.transform.regex(
                iam_policy_resource["StackResourceDetail"]["PhysicalResourceId"],
                "<iam-policy-physicalid>",
            )
        )

        snapshot.match("stack_resources", stack_resources)

        # query service APIs for resource states
        get_function_result = lambda_client.get_function(FunctionName=fn_name)
        get_esm_result = lambda_client.get_event_source_mapping(UUID=esm_id)
        get_queue_atts_result = sqs_client.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["All"]
        )
        role_arn = get_function_result["Configuration"]["Role"]
        role_name = role_arn.partition("role/")[-1]
        get_role_result = iam_client.get_role(RoleName=role_name)
        list_attached_role_policies_result = iam_client.list_attached_role_policies(
            RoleName=role_name
        )
        list_inline_role_policies_result = iam_client.list_role_policies(RoleName=role_name)
        policies = []
        for rp in list_inline_role_policies_result["PolicyNames"]:
            get_rp_result = iam_client.get_role_policy(RoleName=role_name, PolicyName=rp)
            policies.append(get_rp_result)

        snapshot.add_transformer(
            snapshot.transform.jsonpath(
                "$..policies..ResponseMetadata", "<response-metadata>", reference_replacement=False
            )
        )

        snapshot.match("role_policies", {"policies": policies})
        snapshot.match("get_function_result", get_function_result)
        snapshot.match("get_esm_result", get_esm_result)
        snapshot.match("get_queue_atts_result", get_queue_atts_result)
        snapshot.match("get_role_result", get_role_result)
        snapshot.match("list_attached_role_policies_result", list_attached_role_policies_result)
        snapshot.match("list_inline_role_policies_result", list_inline_role_policies_result)

        # TODO: extract
        # TODO: is this even necessary? should the cloudformation deployment guarantee that this is enabled already?
        def wait_esm_active():
            try:
                return lambda_client.get_event_source_mapping(UUID=esm_id)["State"] == "Enabled"
            except Exception as e:
                print(e)

        assert wait_until(wait_esm_active)

        msg = f"msg-verification-{short_uid()}"
        sqs_client.send_message(QueueUrl=queue_url, MessageBody=msg)

        # TODO: extract
        def wait_logs():
            log_events = logs_client.filter_log_events(logGroupName=f"/aws/lambda/{fn_name}")[
                "events"
            ]
            return any([msg in e["message"] for e in log_events])

        assert wait_until(wait_logs)
