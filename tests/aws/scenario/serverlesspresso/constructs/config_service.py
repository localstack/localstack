import os

import aws_cdk as cdk
import constructs

from localstack.utils.files import load_file


class ConfigService(constructs.Construct):
    def __init__(
        self, scope: constructs.Construct, id: str, *, source: str, bucket_name: str, event_bus
    ):
        super().__init__(scope, id)

        # ================================================================================================
        # config service
        # ================================================================================================

        self.config_table = config_table = cdk.aws_dynamodb.Table(
            self,
            "ConfigTable",
            table_name="serverlesspresso-config-table",
            billing_mode=cdk.aws_dynamodb.BillingMode.PAY_PER_REQUEST,
            stream=cdk.aws_dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            partition_key=cdk.aws_dynamodb.Attribute(
                name="PK", type=cdk.aws_dynamodb.AttributeType.STRING
            ),
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        api_def = load_file(
            os.path.join(os.path.dirname(__file__), "../artifacts/api/config-service-api.yaml")
        )
        # rest_api_config_service = cdk.aws_apigateway.SpecRestApi(
        #     self,
        #     "RESTApConfigService",
        #     deploy_options=cdk.aws_apigateway.StageOptions(stage_name="Prod"),
        #     # api_definition=cdk.aws_apigateway.ApiDefinition.from_inline(api_def)  # TODO: definition includes CFn so we might have to unwrap it and define it completely in CDK
        # )

        rest_api_config_service = cdk.aws_apigateway.CfnRestApi(
            self,
            "RESTApConfigService",
            body=cdk.Fn.transform(
                "AWS::Include",
                {
                    "Location": cdk.Fn.join(
                        "", ["s3://", bucket_name, "/api/config_service_api.yaml"]
                    )
                },
            ),
        )

        config_changed_fn_handler = load_file(
            os.path.join(os.path.dirname(__file__), "../artifacts/functions/configChanged.js")
        )
        config_changed_fn = cdk.aws_lambda.Function(
            self,
            "ConfigChangedFunction",
            runtime=cdk.aws_lambda.Runtime.NODEJS_14_X,
            handler="index.handler",
            code=cdk.aws_lambda.Code.from_inline(code=config_changed_fn_handler),
            environment={
                "EventBusName": event_bus.event_bus_name,
                "Source": source,
            },
            timeout=cdk.Duration.seconds(15),
        )
        event_bus.grant_put_events_to(config_changed_fn)
        config_table.grant_read_data(config_changed_fn)
        config_changed_fn.add_event_source(
            cdk.aws_lambda_event_sources.DynamoEventSource(
                table=config_table,
                batch_size=1,
                starting_position=cdk.aws_lambda.StartingPosition.TRIM_HORIZON,
            )
        )

        # TODO: StoreFunction: PUT /Store?state=false
        # TODO: GetConfigFunction: GET /config
        # TODO: GetAdminConfigFunction: GET /admin-config

        # ================================================================================================
        # config API role
        # ================================================================================================

        config_rest_api_role = cdk.aws_iam.Role(
            self,
            "ConfigRESTApiRole",
            assumed_by=cdk.aws_iam.ServicePrincipal("apigateway.amazonaws.com"),
            inline_policies={
                "DynamoDBinteraction": cdk.aws_iam.PolicyDocument(
                    statements=[
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=[
                                "dynamodb:Scan",
                                "dynamodb:GetItem",
                                "dynamodb:UpdateItem",
                            ],
                            resources=[config_table.table_arn],
                        ),
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=[
                                "dynamodb:Query",
                            ],
                            resources=["*"],  # TODO stricter
                        ),
                    ]
                )
            },
        )
        config_rest_api_role.node.default_child.override_logical_id("ConfigRESTApiRole")
