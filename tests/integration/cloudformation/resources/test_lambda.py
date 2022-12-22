import base64
import json
import os

import pytest

from localstack.aws.api.lambda_ import InvocationType, State
from localstack.testing.aws.lambda_utils import is_new_provider, is_old_provider
from localstack.testing.snapshots.transformer import SortingTransformer
from localstack.utils.common import short_uid
from localstack.utils.http import safe_requests
from localstack.utils.strings import to_bytes, to_str
from localstack.utils.sync import retry, wait_until
from localstack.utils.testutil import get_lambda_log_events


@pytest.mark.skipif(condition=is_new_provider(), reason="not implemented yet")
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
@pytest.mark.aws_validated
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


@pytest.mark.aws_validated
def test_lambda_alias(deploy_cfn_template, cfn_client, lambda_client, snapshot):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.lambda_api())
    snapshot.add_transformer(
        SortingTransformer("StackResources", lambda x: x["LogicalResourceId"]), priority=-1
    )

    function_name = f"function{short_uid()}"
    alias_name = f"alias{short_uid()}"
    snapshot.add_transformer(snapshot.transform.regex(alias_name, "<alias-name>"))
    snapshot.add_transformer(snapshot.transform.regex(function_name, "<function-name>"))

    deployment = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/cfn_lambda_alias.yml"
        ),
        parameters={"FunctionName": function_name, "AliasName": alias_name},
    )

    role_arn = lambda_client.get_function(FunctionName=function_name)["Configuration"]["Role"]
    snapshot.add_transformer(
        snapshot.transform.regex(role_arn.partition("role/")[-1], "<role-name>"), priority=-1
    )

    description = cfn_client.describe_stack_resources(StackName=deployment.stack_name)
    snapshot.match("stack_resource_descriptions", description)

    alias = lambda_client.get_alias(FunctionName=function_name, Name=alias_name)
    snapshot.match("Alias", alias)


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(paths=["$..DestinationConfig"])
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


@pytest.mark.skip_snapshot_verify(condition=is_old_provider, paths=["$..DestinationConfig"])
@pytest.mark.aws_validated
def test_event_invoke_config(deploy_cfn_template, lambda_client, snapshot):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.lambda_api())

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/cfn_lambda_event_invoke_config.yml"
        ),
        max_wait=180,
    )

    event_invoke_config = lambda_client.get_function_event_invoke_config(
        FunctionName=stack.outputs["FunctionName"],
        Qualifier=stack.outputs["FunctionQualifier"],
    )

    snapshot.match("event_invoke_config", event_invoke_config)


@pytest.mark.skip_snapshot_verify(paths=["$..CodeSize"])
@pytest.mark.skip_snapshot_verify(
    condition=is_old_provider,
    paths=[
        "$..Versions..Description",
        "$..Versions..EphemeralStorage",
        "$..Versions..LastUpdateStatus",
        "$..Versions..MemorySize",
        "$..Versions..State",
        "$..Versions..VpcConfig",
        "$..Code.RepositoryType",
        "$..Configuration.Description",
        "$..Configuration.EphemeralStorage",
        "$..Configuration.FunctionArn",
        "$..Configuration.MemorySize",
        "$..Configuration.RevisionId",
        "$..Configuration.Version",
        "$..Configuration.VpcConfig",
        "$..Tags",
        "$..Layers",
    ],
)
@pytest.mark.aws_validated
def test_lambda_version(deploy_cfn_template, cfn_client, lambda_client, snapshot):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.lambda_api())
    snapshot.add_transformer(
        SortingTransformer("StackResources", lambda sr: sr["LogicalResourceId"])
    )
    snapshot.add_transformer(snapshot.transform.key_value("CodeSha256"))

    deployment = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/cfn_lambda_version.yaml"
        ),
        max_wait=240,
    )

    invoke_result = lambda_client.invoke(
        FunctionName=deployment.outputs["FunctionName"], Payload=b"{}"
    )
    assert 200 <= invoke_result["StatusCode"] < 300

    stack_resources = cfn_client.describe_stack_resources(StackName=deployment.stack_id)
    snapshot.match("stack_resources", stack_resources)

    function_name = deployment.outputs["FunctionName"]
    function_version = deployment.outputs["FunctionVersion"]
    versions_by_fn = lambda_client.list_versions_by_function(FunctionName=function_name)
    get_function_version = lambda_client.get_function(
        FunctionName=function_name, Qualifier=function_version
    )

    snapshot.match("versions_by_fn", versions_by_fn)
    snapshot.match("get_function_version", get_function_version)


@pytest.mark.aws_validated
def test_lambda_cfn_run(deploy_cfn_template, lambda_client):
    """
    simply deploys a lambda and immediately invokes it
    """
    deployment = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/cfn_lambda_simple.yaml"
        ),
        max_wait=120,
    )
    fn_name = deployment.outputs["FunctionName"]
    assert (
        lambda_client.get_function(FunctionName=fn_name)["Configuration"]["State"] == State.Active
    )
    lambda_client.invoke(FunctionName=fn_name, LogType="Tail", Payload=b"{}")


@pytest.mark.skip(reason="broken/notimplemented")
@pytest.mark.aws_validated
def test_lambda_vpc(deploy_cfn_template, lambda_client):
    """
    this test showcases a very long-running deployment of a fairly straight forward lambda function
    cloudformation will poll get_function until the active state has been reached
    """
    fn_name = f"vpc-lambda-fn-{short_uid()}"
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/cfn_lambda_vpc.yaml"
        ),
        parameters={
            "FunctionNameParam": fn_name,
        },
        max_wait=600,
    )
    assert (
        lambda_client.get_function(FunctionName=fn_name)["Configuration"]["State"] == State.Active
    )
    lambda_client.invoke(FunctionName=fn_name, LogType="Tail", Payload=b"{}")


@pytest.mark.xfail(condition=is_new_provider(), reason="fails/times out with new provider")
@pytest.mark.skip_snapshot_verify(
    paths=[
        "$..Policy.PolicyArn",
        "$..Policy.PolicyName",
        "$..Policy.Statement..Resource",
        "$..Policy.Statement..Sid",
        "$..RevisionId",
    ]
)
def test_update_lambda_permissions(deploy_cfn_template, lambda_client, sts_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/cfn_lambda_permission.yml"
        )
    )

    new_principal = sts_client.get_caller_identity()["Account"]

    deploy_cfn_template(
        is_update=True,
        stack_name=stack.stack_name,
        parameters={"PrincipalForPermission": new_principal},
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/cfn_lambda_permission.yml"
        ),
    )

    policy = lambda_client.get_policy(FunctionName=stack.outputs["FunctionName"])

    # The behaviour of thi principal acocunt setting changes with aws or lambda providers
    principal = json.loads(policy["Policy"])["Statement"][0]["Principal"]
    if isinstance(principal, dict):
        principal = principal.get("AWS") or principal.get("Service", "")

    assert new_principal in principal


class TestCfnLambdaIntegrations:
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Policy.PolicyArn",
            "$..Policy.PolicyName",
            "$..Code.RepositoryType",
            "$..Configuration.EphemeralStorage",
            "$..Configuration.MemorySize",
            "$..Configuration.VpcConfig",
        ],
        condition=is_old_provider,
    )
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Attributes.EffectiveDeliveryPolicy",  # broken in sns right now. needs to be wrapped within an http key
            "$..Attributes.DeliveryPolicy",  # shouldn't be there
            "$..Attributes.Policy",  # missing SNS:Receive
            "$..CodeSize",
            "$..Configuration.Layers",
            "$..RevisionId",  # seems the revision id of the policy actually corresponds to the one of the function version
            "$..Tags",  # missing cloudformation automatic resource tags for the lambda function
        ]
    )
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
            SortingTransformer("StackResources", lambda sr: sr["LogicalResourceId"]), priority=-1
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

    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..Code.RepositoryType",
            "$..Configuration.EphemeralStorage",
            "$..Configuration.MemorySize",
            "$..Configuration.VpcConfig",
            "$..FunctionResponseTypes",
            "$..LastProcessingResult",
            "$..MaximumBatchingWindowInSeconds",
            "$..MaximumRetryAttempts",
            "$..ParallelizationFactor",
            "$..StartingPosition",
            "$..StateTransitionReason",
            "$..Topics",
        ],
    )
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..MaximumRetryAttempts",
            "$..ParallelizationFactor",
            "$..StateTransitionReason",
            # Lambda
            "$..Tags",
            "$..Configuration.CodeSize",
            "$..Configuration.Layers",
            # SQS
            "$..Attributes.SqsManagedSseEnabled",
            # # IAM
            "$..PolicyNames",
            "$..PolicyName",
            "$..Role.Description",
            "$..Role.MaxSessionDuration",
            "$..StackResources..PhysicalResourceId",  # TODO: compatibility between AWS URL and localstack URL
        ]
    )
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
            SortingTransformer("StackResources", lambda sr: sr["LogicalResourceId"]), priority=-1
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

        deployment.destroy()
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException):
            lambda_client.get_event_source_mapping(UUID=esm_id)

    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..Code.RepositoryType",
            "$..Configuration.EphemeralStorage",
            "$..Configuration.MemorySize",
            "$..Configuration.VpcConfig",
            "$..FunctionResponseTypes",
            "$..LastProcessingResult",
            "$..MaximumBatchingWindowInSeconds",
            "$..MaximumRetryAttempts",
            "$..ParallelizationFactor",
            "$..StartingPosition",
            "$..StateTransitionReason",
            "$..Topics",
        ],
    )
    @pytest.mark.skip_snapshot_verify(
        paths=[
            # Lambda
            "$..Tags",
            "$..Configuration.CodeSize",
            "$..Configuration.Layers",
            # IAM
            "$..PolicyNames",
            "$..policies..PolicyName",
            "$..Role.Description",
            "$..Role.MaxSessionDuration",
            "$..StackResources..LogicalResourceId",
            "$..StackResources..PhysicalResourceId",
            # dynamodb describe_table
            "$..Table.ProvisionedThroughput.LastDecreaseDateTime",
            "$..Table.ProvisionedThroughput.LastIncreaseDateTime",
            # stream result
            "$..StreamDescription.CreationRequestDateTime",
            # event source mapping
            "$..BisectBatchOnFunctionError",
            "$..DestinationConfig",
            "$..LastProcessingResult",
            "$..MaximumRecordAgeInSeconds",
            "$..TumblingWindowInSeconds",
        ]
    )
    @pytest.mark.aws_validated
    def test_cfn_lambda_dynamodb_source(
        self,
        deploy_cfn_template,
        cfn_client,
        lambda_client,
        dynamodb_client,
        dynamodbstreams_client,
        logs_client,
        iam_client,
        snapshot,
    ):
        """
        Resources:
        * Lambda Function
        * DynamoDB Table + Stream
        * EventSourceMapping
        * IAM Roles/Policies (e.g. dynamodb:GetRecords for lambda service to poll dynamodb)
        """

        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.dynamodb_api())
        snapshot.add_transformer(
            SortingTransformer("StackResources", lambda sr: sr["LogicalResourceId"]), priority=-1
        )
        snapshot.add_transformer(snapshot.transform.key_value("CodeSha256"))
        snapshot.add_transformer(snapshot.transform.key_value("RoleId"))
        snapshot.add_transformer(
            snapshot.transform.key_value("ShardId", reference_replacement=False)
        )
        snapshot.add_transformer(
            snapshot.transform.key_value("StartingSequenceNumber", reference_replacement=False)
        )

        deployment = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/cfn_lambda_dynamodb_source.yaml"
            ),
            max_wait=240,
        )
        fn_name = deployment.outputs["FunctionName"]
        table_name = deployment.outputs["TableName"]
        stream_arn = deployment.outputs["StreamArn"]
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

        describe_table_result = dynamodb_client.describe_table(TableName=table_name)
        describe_stream_result = dynamodbstreams_client.describe_stream(StreamArn=stream_arn)
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
        snapshot.match("describe_table_result", describe_table_result)
        snapshot.match("describe_stream_result", describe_stream_result)
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
        dynamodb_client.put_item(
            TableName=table_name, Item={"id": {"S": "test"}, "msg": {"S": msg}}
        )

        # TODO: extract
        def wait_logs():
            log_events = logs_client.filter_log_events(logGroupName=f"/aws/lambda/{fn_name}")[
                "events"
            ]
            return any([msg in e["message"] for e in log_events])

        assert wait_until(wait_logs)

        deployment.destroy()
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException):
            lambda_client.get_event_source_mapping(UUID=esm_id)

    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..Code.RepositoryType",
            "$..Configuration.EphemeralStorage",
            "$..Configuration.MemorySize",
            "$..Configuration.VpcConfig",
            "$..FunctionResponseTypes",
            "$..MaximumBatchingWindowInSeconds",
            "$..Topics",
        ],
    )
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Role.Description",
            "$..Role.MaxSessionDuration",
            "$..BisectBatchOnFunctionError",
            "$..DestinationConfig",
            "$..LastProcessingResult",
            "$..MaximumRecordAgeInSeconds",
            "$..Configuration.CodeSize",
            "$..Tags",
            "$..StreamDescription.StreamModeDetails",
            "$..Configuration.Layers",
            "$..TumblingWindowInSeconds",
            # flaky because we currently don't actually wait in cloudformation for it to be active
            "$..Configuration.LastUpdateStatus",
            "$..Configuration.State",
            "$..Configuration.StateReason",
            "$..Configuration.StateReasonCode",
        ],
    )
    @pytest.mark.aws_validated
    def test_cfn_lambda_kinesis_source(
        self,
        deploy_cfn_template,
        cfn_client,
        lambda_client,
        kinesis_client,
        logs_client,
        iam_client,
        snapshot,
    ):
        """
        Resources:
        * Lambda Function
        * Kinesis Stream
        * EventSourceMapping
        * IAM Roles/Policies (e.g. kinesis:GetRecords for lambda service to poll kinesis)
        """

        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.kinesis_api())
        snapshot.add_transformer(
            SortingTransformer("StackResources", lambda sr: sr["LogicalResourceId"]), priority=-1
        )
        snapshot.add_transformer(snapshot.transform.key_value("CodeSha256"))
        snapshot.add_transformer(snapshot.transform.key_value("RoleId"))
        snapshot.add_transformer(
            snapshot.transform.key_value("ShardId", reference_replacement=False)
        )
        snapshot.add_transformer(
            snapshot.transform.key_value("StartingSequenceNumber", reference_replacement=False)
        )

        deployment = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/cfn_lambda_kinesis_source.yaml"
            ),
            max_wait=240,
        )
        fn_name = deployment.outputs["FunctionName"]
        stream_name = deployment.outputs["StreamName"]
        # stream_arn = deployment.outputs["StreamArn"]
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
        describe_stream_result = kinesis_client.describe_stream(StreamName=stream_name)
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
        snapshot.match("describe_stream_result", describe_stream_result)
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
        data_msg = to_str(base64.b64encode(to_bytes(msg)))
        kinesis_client.put_record(
            StreamName=stream_name, Data=msg, PartitionKey="samplepartitionkey"
        )

        # TODO: extract
        def wait_logs():
            log_events = logs_client.filter_log_events(logGroupName=f"/aws/lambda/{fn_name}")[
                "events"
            ]
            return any([data_msg in e["message"] for e in log_events])

        assert wait_until(wait_logs)

        deployment.destroy()

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException):
            lambda_client.get_event_source_mapping(UUID=esm_id)


class TestCfnLambdaDestinations:
    """
    generic cases
    1. verify payload

    - [ ] SNS destination success
    - [ ] SNS destination failure
    - [ ] SQS destination success
    - [ ] SQS destination failure
    - [ ] Lambda destination success
    - [ ] Lambda destination failure
    - [ ] EventBridge destination success
    - [ ] EventBridge destination failure

    meta cases
    * test max event age
    * test retry count
    * qualifier issues
    * reserved concurrency set to 0 => should immediately go to failure destination / dlq
    * combination with DLQ
    * test with a very long queue (reserved concurrency 1, high function duration, low max event age)

    edge cases
    - [ ] Chaining async lambdas

    doc:
    "If the function doesn't have enough concurrency available to process all events, additional requests are throttled.
    For throttling errors (429) and system errors (500-series), Lambda returns the event to the queue and attempts to run the function again for up to 6 hours.
    The retry interval increases exponentially from 1 second after the first attempt to a maximum of 5 minutes.
    If the queue contains many entries, Lambda increases the retry interval and reduces the rate at which it reads events from the queue."

    """

    @pytest.mark.skip(reason="not supported atm and test needs further work")
    @pytest.mark.parametrize(
        ["on_success", "on_failure"],
        [
            ("sqs", "sqs"),
            # ("sns", "sns"),
            # ("lambda", "lambda"),
            # ("eventbridge", "eventbridge")
        ],
    )
    @pytest.mark.aws_validated
    def test_generic_destination_routing(
        self, lambda_client, logs_client, deploy_cfn_template, cfn_client, on_success, on_failure
    ):
        """
        This fairly simple template lets us choose between the 4 different destinations for both OnSuccess as well as OnFailure.
        The template chooses between one of 4 ARNs via indexed access according to this mapping:

        0: SQS
        1: SNS
        2: Lambda
        3: EventBridge

        All of them are connected downstream to another Lambda function.
        This function can be used to verify that the payload has propagated through the hole scenario.
        It also allows us to verify the specific payload format depending on the service integration.

                       │
                       ▼
                    Lambda
                       │
            ┌──────┬───┴───┬───────┐
            │      │       │       │
            ▼      ▼       ▼       ▼
        (direct)  SQS     SNS  EventBridge
            │      │       │       │
            │      │       │       │
            └──────┴───┬───┴───────┘
                       │
                       ▼
                     Lambda

        # TODO: fix eventbridge name (reuse?)
        """

        name_to_index_map = {"sqs": "0", "sns": "1", "lambda": "2", "eventbridge": "3"}

        deployment = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/cfn_lambda_destinations.yaml"
            ),
            parameters={
                # "RetryParam": "",
                # "MaxEventAgeSecondsParam": "",
                # "QualifierParameter": "",
                "OnSuccessSwitch": name_to_index_map[on_success],
                "OnFailureSwitch": name_to_index_map[on_failure],
            },
            max_wait=600,
        )

        invoke_fn_name = deployment.outputs["LambdaName"]
        collect_fn_name = deployment.outputs["CollectLambdaName"]

        msg = f"message-{short_uid()}"

        # Success case
        lambda_client.invoke(
            FunctionName=invoke_fn_name,
            Payload=to_bytes(json.dumps({"message": msg, "should_fail": "0"})),
            InvocationType=InvocationType.Event,
        )

        # Failure case
        lambda_client.invoke(
            FunctionName=invoke_fn_name,
            Payload=to_bytes(json.dumps({"message": msg, "should_fail": "1"})),
            InvocationType=InvocationType.Event,
        )

        def wait_for_logs():
            events = logs_client.filter_log_events(logGroupName=f"/aws/lambda/{collect_fn_name}")[
                "events"
            ]
            message_events = [e["message"] for e in events if msg in e["message"]]
            return len(message_events) >= 2
            # return len(events) >= 6  # note: each invoke comes with at least 3 events even without printing

        wait_until(wait_for_logs)
