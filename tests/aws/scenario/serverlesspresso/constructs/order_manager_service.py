import os

import aws_cdk as cdk
import constructs

from localstack.utils.files import load_file


class OrderManagerService(constructs.Construct):
    def __init__(
        self,
        scope: constructs.Construct,
        id: str,
        *,
        source: str,
        bucket_name: str,
        event_bus,
        config_table,
    ):
        super().__init__(scope, id)

        self.order_table = order_table = cdk.aws_dynamodb.Table(
            self,
            "OrderTable",
            table_name="serverlesspresso-order-table",
            removal_policy=cdk.RemovalPolicy.DESTROY,
            billing_mode=cdk.aws_dynamodb.BillingMode.PAY_PER_REQUEST,
            partition_key=cdk.aws_dynamodb.Attribute(
                name="PK", type=cdk.aws_dynamodb.AttributeType.STRING
            ),
            sort_key=cdk.aws_dynamodb.Attribute(
                name="SK", type=cdk.aws_dynamodb.AttributeType.STRING
            ),
            stream=cdk.aws_dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
        )
        order_table.add_local_secondary_index(
            index_name="LSI-timestamp",
            sort_key=cdk.aws_dynamodb.Attribute(
                name="TS", type=cdk.aws_dynamodb.AttributeType.NUMBER
            ),
            projection_type=cdk.aws_dynamodb.ProjectionType.ALL,
        )
        order_table.add_global_secondary_index(
            index_name="GSI-status",
            partition_key=cdk.aws_dynamodb.Attribute(
                name="ORDERSTATE", type=cdk.aws_dynamodb.AttributeType.STRING
            ),
            sort_key=cdk.aws_dynamodb.Attribute(
                name="SK", type=cdk.aws_dynamodb.AttributeType.STRING
            ),
            projection_type=cdk.aws_dynamodb.ProjectionType.ALL,
        )
        order_table.add_global_secondary_index(
            index_name="GSI-userId",
            partition_key=cdk.aws_dynamodb.Attribute(
                name="USERID", type=cdk.aws_dynamodb.AttributeType.STRING
            ),
            sort_key=cdk.aws_dynamodb.Attribute(
                name="SK", type=cdk.aws_dynamodb.AttributeType.STRING
            ),
            projection_type=cdk.aws_dynamodb.ProjectionType.ALL,
        )

        validator_new_order_fn_handler = load_file(
            os.path.join(os.path.dirname(__file__), "../artifacts/functions/newOrder.js")
        )
        validator_new_order_fn = cdk.aws_lambda.Function(
            self,
            "ValidatorNewOrderFunction",
            runtime=cdk.aws_lambda.Runtime.NODEJS_18_X,
            handler="index.handler",
            code=cdk.aws_lambda.Code.from_inline(code=validator_new_order_fn_handler),
            environment={
                "TableName": order_table.table_name,
            },
            timeout=cdk.Duration.seconds(15),
        )
        order_table.grant_write_data(validator_new_order_fn)

        sanitize_order_fn_handler = load_file(
            os.path.join(
                os.path.dirname(__file__),
                "../artifacts/functions/sanitize.py",  # TODO: remove dependency(!)
            )
        )
        sanitize_order_fn = cdk.aws_lambda.Function(
            self,
            "SanitizeOrderLambda",
            runtime=cdk.aws_lambda.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=cdk.aws_lambda.Code.from_inline(code=sanitize_order_fn_handler),
            timeout=cdk.Duration.seconds(20),
        )

        get_order_by_id_fn_handler = load_file(
            os.path.join(os.path.dirname(__file__), "../artifacts/functions/getById.js")
        )
        get_order_by_id_fn = cdk.aws_lambda.Function(
            self,
            "GetOrderByIdFunction",
            runtime=cdk.aws_lambda.Runtime.NODEJS_18_X,
            handler="index.handler",
            code=cdk.aws_lambda.Code.from_inline(code=get_order_by_id_fn_handler),
            timeout=cdk.Duration.seconds(15),
        )

        workflow_started_fn_handler = load_file(
            os.path.join(os.path.dirname(__file__), "../artifacts/functions/workflowStarted.js")
        )
        self.workflow_started_fn = workflow_started_fn = cdk.aws_lambda.Function(
            self,
            "WorkFlowStarted",
            runtime=cdk.aws_lambda.Runtime.NODEJS_18_X,
            handler="index.handler",
            code=cdk.aws_lambda.Code.from_inline(code=workflow_started_fn_handler),
            timeout=cdk.Duration.seconds(15),
            environment={
                "TableName": order_table.table_name,
            },
        )
        order_table.grant_write_data(workflow_started_fn)

        waiting_completion_fn_handler = load_file(
            os.path.join(os.path.dirname(__file__), "../artifacts/functions/waitingCompletion.js")
        )
        waiting_completion_fn = cdk.aws_lambda.Function(
            self,
            "WaitingCompletion",
            runtime=cdk.aws_lambda.Runtime.NODEJS_18_X,
            handler="index.handler",
            code=cdk.aws_lambda.Code.from_inline(code=waiting_completion_fn_handler),
            timeout=cdk.Duration.seconds(15),
            environment={
                "TableName": order_table.table_name,
                "BusName": event_bus.event_bus_name,
                "Source": source,
            },
        )
        order_table.grant_write_data(waiting_completion_fn)
        event_bus.grant_put_events_to(waiting_completion_fn)

        # RESTApiForOrderManager
        self.order_manager_api = cdk.aws_apigateway.CfnRestApi(
            self,
            "RESTApiForOrderManager",
            body=cdk.Fn.transform(
                "AWS::Include",
                {
                    "Location": cdk.Fn.join(
                        "", ["s3://", bucket_name, "/api/order_manager_api.yaml"]
                    )
                },
            ),
        )

        cdk.aws_apigateway.CfnDeployment(
            self,
            "Deployment",
            rest_api_id=self.order_manager_api.attr_rest_api_id,
            stage_name="Prod",
        )

        # cdk.aws_apigateway.CfnStage(self, "Stage", stage_name="Prod", deployment_id=deployment.attr_deployment_id, rest_api_id=self.order_manager_api.attr_rest_api_id)

        # 02OrderManagerStateMachine
        order_state_machine_definition = load_file(
            os.path.join(
                os.path.dirname(__file__), "../artifacts/statemachine/order_state_machine.asl.json"
            )
        )
        self.order_state_machine = order_state_machine = cdk.aws_stepfunctions.StateMachine(
            self,
            "OrderManagerStateMachine",
            definition_body=cdk.aws_stepfunctions.DefinitionBody.from_string(
                order_state_machine_definition
            ),
            definition_substitutions={
                "OMTable": order_table.table_name,
                "ConfigTable": config_table.table_name,
                "SanitizeOrderLambda": sanitize_order_fn.function_name,
            },
        )
        order_state_machine.node.default_child.override_logical_id("OrderManagerStateMachine")
        order_state_machine.grant_task_response(cdk.aws_iam.AnyPrincipal())
        event_bus.grant_put_events_to(order_state_machine)
        sanitize_order_fn.grant_invoke(order_state_machine)
        config_table.grant_read_data(order_state_machine)
        order_table.grant_write_data(order_state_machine)

        # RESTApiRole
        rest_api_role = cdk.aws_iam.Role(
            self,
            "RESTApiRole",
            assumed_by=cdk.aws_iam.ServicePrincipal("apigateway.amazonaws.com"),
            inline_policies={
                "DynamoDBinteraction": cdk.aws_iam.PolicyDocument(
                    statements=[
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["states:StartExecution"],
                            resources=[order_state_machine.state_machine_arn],
                        ),
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["dynamodb:GetItem", "dynamodb:Query"],
                            resources=[order_table.table_arn],
                        ),
                    ]
                )
            },
        )
        rest_api_role.node.default_child.override_logical_id("RESTApiRole")
