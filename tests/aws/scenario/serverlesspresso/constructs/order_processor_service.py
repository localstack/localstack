import aws_cdk as cdk
import aws_cdk.aws_stepfunctions as sfn
import aws_cdk.aws_stepfunctions_tasks as tasks
import constructs


class OrderProcessorService(constructs.Construct):
    def __init__(
        self,
        scope: constructs.Construct,
        id: str,
        *,
        source,
        max_concurrent_capacity,
        event_bus,
        config_table,
        counting_table,
        order_state_machine,
        workflow_started_fn,
    ):
        super().__init__(scope, id)

        # ================================================================================================
        # order processor IAM role
        # ================================================================================================

        # TODO Find the place where is used.
        cdk.aws_iam.Policy(
            self,
            "RolePolicies",
            policy_name="orderProcessorWFPolicy",
            document=cdk.aws_iam.PolicyDocument(
                statements=[
                    cdk.aws_iam.PolicyStatement(
                        effect=cdk.aws_iam.Effect.ALLOW,
                        actions=["events:PutEvents"],
                        resources=[event_bus.event_bus_arn],
                    ),
                    cdk.aws_iam.PolicyStatement(
                        effect=cdk.aws_iam.Effect.ALLOW,
                        actions=[
                            "dynamodb:GetItem",
                            "dynamodb:UpdateItem",
                        ],
                        resources=[config_table.table_arn],
                    ),
                    cdk.aws_iam.PolicyStatement(
                        effect=cdk.aws_iam.Effect.ALLOW,
                        actions=["dynamodb:UpdateItem"],
                        resources=[counting_table.table_arn],
                    ),
                    cdk.aws_iam.PolicyStatement(
                        effect=cdk.aws_iam.Effect.ALLOW,
                        actions=["states:ListExecutions"],
                        resources=["*"],  # TODO: no 100% correct
                    ),
                ]
            ),
        )

        # ================================================================================================
        # workshop content
        # ================================================================================================

        get_item_task = tasks.DynamoGetItem(
            self,
            "DynamoDB Get Shop status",
            table=config_table,
            key={"PK": tasks.DynamoAttributeValue.from_string("config")},
            result_path="$.GetStore",
        )
        emit_workflow_started_task = tasks.EventBridgePutEvents(
            self,
            "Emit - Workflow Started TT",
            entries=[
                tasks.EventBridgePutEventsEntry(
                    detail=sfn.TaskInput.from_object(
                        {
                            "Message": "The workflow waits for your order to be submitted. It emits an event with a unique 'task token'. The token is stored in an Amazon DynamoDB table, along with your order ID.",
                            "TaskToken": sfn.JsonPath.task_token,
                            "orderId.$": "$.detail.orderId",
                            "userId.$": "$.detail.userId",
                        }
                    ),
                    detail_type="OrderProcessor.WorkflowStarted",
                    event_bus=event_bus,
                    source="lstesting.serverlesspresso",
                ),
            ],
            integration_pattern=sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
            heartbeat_timeout=sfn.Timeout.duration(cdk.Duration.seconds(300)),
            result_path=sfn.JsonPath.DISCARD,
        )
        catch_pass = sfn.Pass(self, "Customer timedout")
        emit_error_timeout = tasks.EventBridgePutEvents(
            self,
            "Emit - error timeout",
            entries=[
                tasks.EventBridgePutEventsEntry(
                    detail=sfn.TaskInput.from_object(
                        {
                            "Message": "The order timed out. Step Functions waits a set amount of time (5 minutes for a customer, 15 minutes for a barista), no action was taken and so the order is ended.",
                            "userId.$": "$.detail.userId",
                            "orderId.$": "$.detail.orderId",
                            "cause.$": "$.cause",
                        }
                    ),
                    detail_type="OrderProcessor.OrderTimeOut",
                    event_bus=event_bus,
                    source="lstesting.serverlesspresso",
                ),
            ],
            result_path="$.order",
            heartbeat_timeout=sfn.Timeout.duration(cdk.Duration.seconds(900)),
        )
        emit_workflow_started_task.add_catch(catch_pass)
        catch_pass.next(emit_error_timeout)

        list_executions_task = tasks.CallAwsService(
            self,
            "ListExecutions",
            action="listExecutions",
            service="sfn",
            parameters={
                "StateMachineArn.$": "$$.StateMachine.Id",
                "MaxResults": 100,
                "StatusFilter": "RUNNING",
            },
            result_path="$.isCapacityAvailable",
            iam_action="states:ListExecutions",
            iam_resources=["*"],
        )

        # otherwise
        emit_order_finished_task = tasks.EventBridgePutEvents(
            self,
            "Emit - order finished",
            entries=[
                tasks.EventBridgePutEventsEntry(
                    detail=sfn.TaskInput.from_object(
                        {
                            "Message": "The order has reached the end of the workflow, and so a final event is emitted to alert other services to this.",
                            "userId.$": "$.detail.userId",
                            "orderId.$": "$.detail.orderId",
                        }
                    ),
                    detail_type="OrderProcessor.orderFinished",
                    event_bus=event_bus,
                    source="lstesting.serverlesspresso",
                ),
            ],
            result_path="$.order",
        )
        pass_task = sfn.Pass(self, "Pass")
        pass_task.next(emit_order_finished_task)

        is_capacity_available = sfn.Choice(
            self,
            "Is capacity available?",
        )

        emit_shop_not_ready_task = tasks.EventBridgePutEvents(
            self,
            "Emit - Shop not ready",
            entries=[
                tasks.EventBridgePutEventsEntry(
                    detail=sfn.TaskInput.from_object(
                        {
                            "Message": "The Step functions workflow checks if the shop is open and has capacity to serve a new order by invoking a Lambda function that queries the Shop config service. The shop was not ready, and so a 'not ready' event is emitted to cancel the current order.",
                            "userId.$": "$.detail.userId",
                        }
                    ),
                    detail_type="OrderProcessor.ShopUnavailable",
                    event_bus=event_bus,
                    source="lstesting.serverlesspresso",
                ),
            ],
        )

        is_capacity_available.when(
            sfn.Condition.is_present(
                f"$.isCapacityAvailable.Executions[{max_concurrent_capacity}]"
            ),
            emit_shop_not_ready_task,
        )

        generate_order_number_task = tasks.DynamoUpdateItem(
            self,
            "Generate Order Number",
            table=counting_table,
            key={"PK": tasks.DynamoAttributeValue.from_string("orderID")},
            update_expression="set IDvalue = IDvalue + :val",
            expression_attribute_values={
                ":val": tasks.DynamoAttributeValue.number_from_string("1")
            },
            return_values=tasks.DynamoReturnValues.UPDATED_NEW,
            result_path="$.Order.Payload",
            result_selector={"orderNumber.$": "$.Attributes.IDvalue.N"},
        )
        emit_workflow_started_task.next(generate_order_number_task)
        emit_waiting_completion_task = tasks.EventBridgePutEvents(
            self,
            "Emit - Waiting Completion TT",
            entries=[
                tasks.EventBridgePutEventsEntry(
                    detail=sfn.TaskInput.from_object(
                        {
                            "Message": "You pressed 'submit order'. The workflow resumes using the stored 'task token', it generates your order number. It then pauses again, emitting an event with a new 'task token'.",
                            "TaskToken": sfn.JsonPath.task_token,
                            "orderId.$": "$.detail.orderId",
                            "orderNumber.$": "$.Order.Payload.orderNumber",
                            "userId.$": "$.detail.userId",
                        }
                    ),
                    detail_type="OrderProcessor.WaitingCompletion",
                    event_bus=event_bus,
                    source="lstesting.serverlesspresso",
                ),
            ],
            result_path="$.order",
            integration_pattern=sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
            heartbeat_timeout=sfn.Timeout.duration(cdk.Duration.seconds(900)),
        )
        emit_waiting_completion_task.next(pass_task)
        generate_order_number_task.next(emit_waiting_completion_task)

        catch_waiting_timeout = sfn.Pass(self, "Barista timedout", input_path="$.cause")
        emit_waiting_completion_task.add_catch(
            catch_waiting_timeout, errors=["States.Timeout"], result_path="$.comment"
        )
        catch_waiting_timeout.next(emit_error_timeout)

        is_capacity_available.otherwise(emit_workflow_started_task)
        list_executions_task.next(is_capacity_available)

        choice = sfn.Choice(self, "Shop open?")
        choice.when(
            sfn.Condition.not_(
                sfn.Condition.boolean_equals("$.GetStore.Item.storeOpen.BOOL", True)
            ),
            emit_shop_not_ready_task,
        )
        choice.otherwise(list_executions_task)
        get_item_task.next(choice)

        self.order_processor_state_machine = order_processor_state_machine = sfn.StateMachine(
            self,
            "OrderProcessorWorkflow",
            state_machine_name="OrderProcessorWorkflow",
            definition_body=sfn.DefinitionBody.from_chainable(get_item_task),
        )
        event_bus.grant_put_events_to(order_processor_state_machine)
        order_processor_state_machine.grant_task_response(order_state_machine)

        # ================================================================================================
        # Workshop 2.New Order
        # ================================================================================================

        validator_to_order_processor_rule = cdk.aws_events.Rule(
            self,
            "NewOrder",
            event_bus=event_bus,
            event_pattern=cdk.aws_events.EventPattern(
                detail_type=["Validator.NewOrder"], source=[source]
            ),
        )
        validator_to_order_processor_rule.add_target(
            cdk.aws_events_targets.SfnStateMachine(machine=order_processor_state_machine)
        )

        workflow_started_rule = cdk.aws_events.Rule(
            self,
            "WorkflowStarted",
            event_bus=event_bus,
            event_pattern=cdk.aws_events.EventPattern(
                detail_type=["OrderProcessor.WorkflowStarted"], source=[source]
            ),
        )
        workflow_started_rule.add_target(cdk.aws_events_targets.LambdaFunction(workflow_started_fn))
