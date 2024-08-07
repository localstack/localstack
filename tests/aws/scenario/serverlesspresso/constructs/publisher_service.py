import os

import aws_cdk as cdk
import constructs

from localstack.utils.files import load_file


class PublisherService(constructs.Construct):
    def __init__(
        self, scope: constructs.Construct, id: str, *, source: str, event_bus, iot_endpoint
    ):
        super().__init__(scope, id)

        # ================================================================================================
        # Publisher service (published to IoT which was setup above)
        # ================================================================================================
        connect_publish_iot_statement = cdk.aws_iam.PolicyStatement(
            effect=cdk.aws_iam.Effect.ALLOW,
            actions=["iot:Connect", "iot:Publish"],
            resources=["arn:aws:iot:*"],
        )

        publisher_function_admin_handler = load_file(
            os.path.join(os.path.dirname(__file__), "../artifacts/functions/publishToIOT.js")
        )
        self.publisher_function_admin = publisher_function_admin = cdk.aws_lambda.Function(
            self,
            "AdminPublisher",
            runtime=cdk.aws_lambda.Runtime.NODEJS_18_X,
            handler="index.handler",
            code=cdk.aws_lambda.Code.from_inline(code=publisher_function_admin_handler),
            environment={
                "IOT_DATA_ENDPOINT": iot_endpoint.get_att(
                    attribute_name="IotEndpointAddress"
                ).to_string(),
                "IOT_TOPIC": "serverlesspresso-admin",
            },
            initial_policy=[connect_publish_iot_statement],
        )
        publisher_admin_rule = cdk.aws_events.Rule(
            self,
            "AdminTriggerRule",
            event_bus=event_bus,
            event_pattern=cdk.aws_events.EventPattern(
                source=[source],
                detail_type=[
                    "prefix: 'OrderManager.'",
                    "prefix: 'OrderProcessor.'",
                    "prefix: 'Validator.'",
                    "prefix: 'ConfigService.'",
                ],
            ),
            targets=[cdk.aws_events_targets.LambdaFunction(publisher_function_admin)],
        )

        publisher_function_user_handler = load_file(
            os.path.join(
                os.path.dirname(__file__), "../artifacts/functions/publishToIOTuserTopic.js"
            )
        )
        self.publisher_function_user = publisher_function_user = cdk.aws_lambda.Function(
            self,
            "UserPublisher",
            runtime=cdk.aws_lambda.Runtime.NODEJS_18_X,
            handler="index.handler",
            code=cdk.aws_lambda.Code.from_inline(code=publisher_function_user_handler),
            environment={
                "IOT_DATA_ENDPOINT": iot_endpoint.get_att(
                    attribute_name="IotEndpointAddress"
                ).to_string(),
                "IOT_TOPIC": "serverlesspresso-user-",
            },
            initial_policy=[connect_publish_iot_statement],
        )
        # why is this separated now?
        order_manager_rule = cdk.aws_events.Rule(
            self,
            "OrderManagerEvents",
            event_bus=event_bus,
            event_pattern=cdk.aws_events.EventPattern(
                source=[source],
                detail_type=[
                    "prefix: 'OrderManager.'",
                ],
            ),
            targets=[cdk.aws_events_targets.LambdaFunction(publisher_function_user)],
        )
        order_processor_rule = cdk.aws_events.Rule(
            self,
            "OrderProcessorEvents",
            event_bus=event_bus,
            event_pattern=cdk.aws_events.EventPattern(
                source=[source],
                detail_type=[
                    "prefix: 'OrderProcessor.'",
                ],
            ),
            targets=[cdk.aws_events_targets.LambdaFunction(publisher_function_user)],
        )

        publisher_function_config_handler = load_file(
            os.path.join(os.path.dirname(__file__), "../artifacts/functions/publishToIOT.js")
        )  # TODO: same as admin?
        self.publisher_function_config = publisher_function_config = cdk.aws_lambda.Function(
            self,
            "ConfigPublisher",
            runtime=cdk.aws_lambda.Runtime.NODEJS_18_X,
            handler="index.handler",
            code=cdk.aws_lambda.Code.from_inline(code=publisher_function_config_handler),
            environment={
                "IOT_DATA_ENDPOINT": iot_endpoint.get_att(
                    attribute_name="IotEndpointAddress"
                ).to_string(),
                "IOT_TOPIC": "serverlesspresso-config",
            },
            initial_policy=[connect_publish_iot_statement],
        )
        trigger_validator_rule = cdk.aws_events.Rule(
            self,
            "TriggerValidator",
            event_bus=event_bus,
            event_pattern=cdk.aws_events.EventPattern(
                source=[source],
                detail_type=[
                    "prefix: 'ConfigService.'",
                ],
            ),
            targets=[cdk.aws_events_targets.LambdaFunction(publisher_function_config)],
        )
