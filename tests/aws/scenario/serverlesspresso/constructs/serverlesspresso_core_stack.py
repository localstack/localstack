import os

import aws_cdk as cdk
import constructs
from aws_cdk.aws_logs import RetentionDays

from localstack.utils.files import load_file
from tests.aws.scenario.serverlesspresso.constructs.auth_service import AuthService
from tests.aws.scenario.serverlesspresso.constructs.config_service import ConfigService
from tests.aws.scenario.serverlesspresso.constructs.order_manager_service import OrderManagerService
from tests.aws.scenario.serverlesspresso.constructs.order_processor_service import (
    OrderProcessorService,
)
from tests.aws.scenario.serverlesspresso.constructs.publisher_service import PublisherService
from tests.aws.scenario.serverlesspresso.constructs.validator_service import ValidatorService

SERVERLESSPRESSO_SOURCE = "lstesting.serverlesspresso"


class ServerlesspressoCoreStack(cdk.Stack):
    #     The initial QR code scan starts the ordering process.
    #     The application checks that the shop is open and the barista’s queue is not full. In this workshop, the barista can only handle up to 20 drinks at a time. If the shop is closed or the queue is full, the order process stops.
    #     It waits 5 minutes for the customer to place the specifics of the drink order, such as a “Vanilla Latte with Soy Milk”. If nothing happens after 5 minutes, the order times out.
    #     It waits 15 minutes for the barista to produce the drink. If nothing happens after 15 minutes, the order times out.
    #     The order is finally completed or canceled by the barista.
    #
    #     Each drink order will be in a separate point of this workflow.
    #     Traditionally, embedding this type of logic in code results in many nested logic branches and relying on a central database to keep track of the state.
    #     Handling timeouts also requires a separate process to take action on workflows that have exceeded their allowed time.
    #     Each drink order is a separate execution of the state machine.

    def __init__(self, scope: constructs.Construct, id: str, *, bucket_name: str, **kwargs):
        super().__init__(scope, id, **kwargs)

        app_name = "Serverlesspresso"  #  Application name (eg. serverlesspresso)
        service = "core"  #  Service name (eg. core)
        time_interval = "5"  # Time interval of buckets (mins)
        code_length = "10"  # Code length in characters
        tokens_per_bucket = "10"  # Tokens in each bucket
        source = SERVERLESSPRESSO_SOURCE  # Event bus source by application
        max_concurrent_capacity = "5"

        # TODO: full counting service
        # counting_service = CountingService(stack, "CountingService", app_name="Serverlesspresso", service="counting", bucket_name=bucket_name)
        counting_table = cdk.aws_dynamodb.Table(
            self,
            "CountingTable",
            table_name="serverlesspresso-counting-table",
            partition_key=cdk.aws_dynamodb.Attribute(
                name="PK", type=cdk.aws_dynamodb.AttributeType.STRING
            ),
            billing_mode=cdk.aws_dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        # ================================================================================================
        # Custom event bus
        # ================================================================================================
        event_bus = cdk.aws_events.EventBus(
            self, "ServerlesspressoEventBus", event_bus_name="Serverlesspresso"
        )
        cdk.aws_ssm.StringParameter(
            self,
            "CoreEventBusNameParameter",
            parameter_name=f"/{app_name}/{service}/eventbusname",
            description="EventBus Name",
            string_value=event_bus.event_bus_name,
        )
        cdk.aws_ssm.StringParameter(
            self,
            "CoreEventBusARNParameter",
            parameter_name=f"/{app_name}/{service}/eventbusarn",
            description="EventBus ARN",
            string_value=event_bus.event_bus_arn,
        )

        # ================================================================================================
        # DEBUG & Introspection
        # ================================================================================================

        debug_log_group = cdk.aws_logs.LogGroup(
            self,
            "DebugLogGroup",
            log_group_name="/aws/events/serverlesspressoEventBus",
            retention=RetentionDays.INFINITE,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        cdk.aws_logs.ResourcePolicy(
            self,
            "logallpolicy",
            resource_policy_name="TrustEventsToStoreLogEvents",
            policy_statements=[
                cdk.aws_iam.PolicyStatement(
                    actions=["logs:*"],
                    resources=[
                        cdk.Fn.join(
                            ":",
                            [
                                "arn:aws:logs",
                                self.region,
                                self.account,
                                "log-group:/aws/events/*:*",
                            ],
                        )
                    ],
                    principals=[
                        cdk.aws_iam.ServicePrincipal("delivery.logs.amazonaws.com"),
                        cdk.aws_iam.ServicePrincipal("events.amazonaws.com"),
                    ],
                    effect=cdk.aws_iam.Effect.ALLOW,
                )
            ],
        )

        cdk.aws_events.CfnRule(
            self,
            "LogAllRule",
            event_bus_name=event_bus.event_bus_name,
            event_pattern={"source": [source]},
            targets=[
                cdk.aws_events.CfnRule.TargetProperty(
                    id="log_to_group", arn=debug_log_group.log_group_arn
                )
            ],
        )

        # ================================================================================================
        # IoT core / MQTT messaging
        # ================================================================================================
        thing = cdk.aws_iot.CfnThing(
            self,
            "ServerlesspressoRealtime",
            thing_name="serverlesspresso-realtime-workshop",
            attribute_payload=cdk.aws_iot.CfnThing.AttributePayloadProperty(attributes={}),
        )
        get_iot_endpoint_handler = load_file(
            os.path.join(os.path.dirname(__file__), "../artifacts/functions/GetIotEndpoint.js")
        )
        get_iot_endpoint_fn = cdk.aws_lambda.Function(
            self,
            "GetIoTEndpointFunction",
            runtime=cdk.aws_lambda.Runtime.NODEJS_18_X,
            handler="index.handler",
            code=cdk.aws_lambda.Code.from_inline(code=get_iot_endpoint_handler),
        )
        get_iot_endpoint_fn.add_to_role_policy(
            cdk.aws_iam.PolicyStatement(
                actions=["iot:DescribeEndpoint"], resources=["*"], effect=cdk.aws_iam.Effect.ALLOW
            )
        )
        iot_endpoint = cdk.CfnCustomResource(
            self, "IotEndpoint", service_token=get_iot_endpoint_fn.function_arn
        )
        cdk.aws_ssm.StringParameter(
            self,
            "IoTRealtimeParameter",
            parameter_name=f"/{app_name}/{service}/realtime",
            description="IoTRealtime URL",
            string_value=iot_endpoint.get_att(attribute_name="IotEndpointAddress").to_string(),
        )

        # ================================================================================================
        # Services
        # ================================================================================================
        publisher_service = PublisherService(
            self, "PublisherService", source=source, event_bus=event_bus, iot_endpoint=iot_endpoint
        )

        auth_service = AuthService(self, "AuthService", app_name=app_name, service=service)
        config_service = ConfigService(
            self, "ConfigService", source=source, bucket_name=bucket_name, event_bus=event_bus
        )
        validator_service = ValidatorService(
            self,
            "ValidatorService",
            source=source,
            tokens_per_bucket=tokens_per_bucket,
            code_length=code_length,
            time_interval=time_interval,
            event_bus=event_bus,
            user_pool=auth_service.user_pool,
        )
        order_manager_service = OrderManagerService(
            self,
            "OrderManagerService",
            source=source,
            event_bus=event_bus,
            bucket_name=bucket_name,
            config_table=config_service.config_table,
        )
        order_processor_service = OrderProcessorService(
            self,
            "OrderProcessorService",
            source=source,
            event_bus=event_bus,
            config_table=config_service.config_table,
            counting_table=counting_table,
            order_state_machine=order_manager_service.order_state_machine,
            workflow_started_fn=order_manager_service.workflow_started_fn,
            max_concurrent_capacity=max_concurrent_capacity,
        )

        # ================================================================================================
        # initial seed data
        # ================================================================================================

        populate_db_fn_handler = load_file(
            os.path.join(os.path.dirname(__file__), "../artifacts/functions/populateDb.js")
        )
        populate_db_fn = cdk.aws_lambda.Function(
            self,
            "PopulateDbFn",
            runtime=cdk.aws_lambda.Runtime.NODEJS_18_X,
            handler="index.handler",
            code=cdk.aws_lambda.Code.from_inline(code=populate_db_fn_handler),
            environment={
                "configTable": config_service.config_table.table_name,
                "countingTable": counting_table.table_name,
            },
        )
        config_service.config_table.grant_read_write_data(populate_db_fn)
        counting_table.grant_read_write_data(populate_db_fn)

        # ================================================================================================
        # OUTPUTS
        # ================================================================================================

        cdk.CfnOutput(
            self,
            "OrderProcessorWorkflowStateMachineArn",
            value=order_processor_service.order_processor_state_machine.state_machine_arn,
        )
        cdk.CfnOutput(
            self,
            "OrderManagerStateMachineArn",
            value=order_manager_service.order_state_machine.state_machine_arn,
        )
        cdk.CfnOutput(self, "PopulateDbFunctionName", value=populate_db_fn.function_name)
        cdk.CfnOutput(self, "ConfigTableName", value=config_service.config_table.table_name)
        cdk.CfnOutput(self, "CountingTableName", value=counting_table.table_name)
        cdk.CfnOutput(self, "OrderTableName", value=order_manager_service.order_table.table_name)
        cdk.CfnOutput(self, "EventBusName", value=event_bus.event_bus_name)
        cdk.CfnOutput(
            self, "AdminFnName", value=publisher_service.publisher_function_admin.function_name
        )
        cdk.CfnOutput(
            self, "UserFnName", value=publisher_service.publisher_function_user.function_name
        )
        cdk.CfnOutput(
            self, "ConfigFnName", value=publisher_service.publisher_function_config.function_name
        )
        cdk.CfnOutput(self, "UserPoolId", value=auth_service.user_pool.user_pool_id)
        cdk.CfnOutput(
            self, "UserPoolClientId", value=auth_service.user_pool_client.user_pool_client_id
        )
        cdk.CfnOutput(
            self, "ValidatorTableName", value=validator_service.validator_table.table_name
        )
        cdk.CfnOutput(self, "LogAllLogGroupName", value=debug_log_group.log_group_name)

        frontends = {
            "DisplayApp": "display",
            "BaristaApp": "barista",
            "OrderApp": "order",
        }

        for frontend, service in frontends.items():
            body = (
                f"https://workshop-{service}.serverlesscoffee.com/?region=${{AWS::Region}}"
                f"&userPoolId=${{UserPoolID}}"
                f"&userPoolWebClientId=${{UserPoolWebClientId}}"
                f"&orderManagerEndpoint=${{OrderManagerEndpoint}}"
                f"&APIGWEndpointValidatorService=${{APIGWEndpointValidatorService}}"
                f"&APIGWEndpointConfigService=${{APIGWEndpointConfigService}}"
                f"&host=${{HostEndpoint}}"
                f"&poolId=${{IdentityPoolId}}"
            )

            cdk.CfnOutput(
                self,
                f"{frontend}URI",
                value=cdk.Fn.sub(
                    body=body,
                    variables={
                        "UserPoolID": auth_service.user_pool.user_pool_id,
                        "UserPoolWebClientId": auth_service.user_pool_client.user_pool_client_id,
                        "OrderManagerEndpoint": cdk.Fn.join(
                            "",
                            [
                                "https://",
                                order_manager_service.order_manager_api.attr_rest_api_id,
                                ".execute-api.",
                                self.region,
                                ".amazonaws.com/Prod",
                            ],
                        ),
                        "APIGWEndpointValidatorService": cdk.Fn.join(
                            "",
                            [
                                "https://",
                                validator_service.rest_api_validator_service.rest_api_id,
                                ".execute-api.",
                                self.region,
                                ".amazonaws.com/Prod",
                            ],
                        ),
                        "APIGWEndpointConfigService": cdk.Fn.join(
                            "",
                            [
                                "https://",
                                config_service.rest_api_config_service.attr_rest_api_id,
                                ".execute-api.",
                                self.region,
                                ".amazonaws.com/Prod",
                            ],
                        ),
                        "HostEndpoint": iot_endpoint.get_att(
                            attribute_name="IotEndpointAddress"
                        ).to_string(),
                        "IdentityPoolId": auth_service.identity_pool.identity_pool_id,
                    },
                ),
            )
