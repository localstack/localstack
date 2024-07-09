"""
TODO: currently not in use
"""

import aws_cdk as cdk
import aws_cdk.aws_dynamodb as dynamodb
import aws_cdk.aws_events as events
import aws_cdk.aws_events_targets as event_targets
import aws_cdk.aws_lambda as lambda_
import aws_cdk.aws_ssm as ssm
import constructs


class CountingService(constructs.Construct):
    def __init__(
        self, scope: constructs.Construct, id: str, *, app_name: str, service: str, bucket_name: str
    ):
        super().__init__(scope, id)

        table = cdk.aws_dynamodb.Table(
            self,
            "DynamoTable",
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            partition_key=dynamodb.Attribute(name="PK", type=dynamodb.AttributeType.STRING),
            # TODO: keyschema?
        )

        asset_bucket = cdk.aws_s3.Bucket.from_bucket_name(
            self, "FunctionBucket", bucket_name=bucket_name
        )
        fn_code = lambda_.S3Code(bucket=asset_bucket, key="functions/counting_service.zip")

        get_order_id_function = lambda_.Function(
            self,
            "GetOrderIdFunction",
            handler="getOrderId.handler",
            runtime=lambda_.Runtime.NODEJS_18_X,
            environment={"AWS_NODEJS_CONNECTION_REUSE_ENABLED": "1", "TableName": table.table_name},
            code=fn_code,
        )

        reset_order_id_function = lambda_.Function(
            self,
            "ResetOrderIdFunction",
            runtime=lambda_.Runtime.NODEJS_18_X,
            handler="resetOrderId.handler",
            code=fn_code,
        )

        event_target = event_targets.LambdaFunction(reset_order_id_function)
        events.Rule(
            self,
            "rule",
            targets=[event_target],
            schedule=events.Schedule.expression("cron(0 7 * * ? *)"),
        )

        ssm.StringParameter(
            self,
            "GetOrderIdFunctionParameter",
            parameter_name=f"/{app_name}/{service}/GetOrderIdFunctionName",
            string_value=get_order_id_function.function_name,
        )

        table.grant_full_access(get_order_id_function)
        table.grant_full_access(reset_order_id_function)

        cdk.CfnOutput(self, "DynamoDbTable", value=table.table_name)
