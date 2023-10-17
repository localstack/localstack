import os

import aws_cdk as cdk
import constructs

from localstack.utils.files import load_file
from tests.aws.scenario.mythical_mysfits.constructs.user_clicks_service import UserClicksService


class MythicalMysfitsCoreStack(cdk.Stack):
    def __init__(self, scope: constructs.Construct, id: str, **kwargs):
        super().__init__(scope, id, **kwargs)

        # TODO: full Mysfits microservice with Fargate + NLB
        mysfits_table = cdk.aws_dynamodb.Table(
            self,
            "MysfitsTable",
            table_name="MysfitsTable",
            partition_key=cdk.aws_dynamodb.Attribute(
                name="MysfitId", type=cdk.aws_dynamodb.AttributeType.STRING
            ),
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        mysfits_table.add_global_secondary_index(
            index_name="LawChaosIndex",
            partition_key=cdk.aws_dynamodb.Attribute(
                name="LawChaos", type=cdk.aws_dynamodb.AttributeType.STRING
            ),
            sort_key=cdk.aws_dynamodb.Attribute(
                name="MysfitId", type=cdk.aws_dynamodb.AttributeType.STRING
            ),
            read_capacity=5,
            write_capacity=5,
            projection_type=cdk.aws_dynamodb.ProjectionType.ALL,
        )
        mysfits_table.add_global_secondary_index(
            index_name="GoodEvilIndex",
            partition_key=cdk.aws_dynamodb.Attribute(
                name="GoodEvil", type=cdk.aws_dynamodb.AttributeType.STRING
            ),
            sort_key=cdk.aws_dynamodb.Attribute(
                name="MysfitId", type=cdk.aws_dynamodb.AttributeType.STRING
            ),
            read_capacity=5,
            write_capacity=5,
            projection_type=cdk.aws_dynamodb.ProjectionType.ALL,
        )

        user_clicks_service = UserClicksService(
            self,
            "UserClicksService",
            account_id=self.account,
            mysfits_table=mysfits_table,
        )

        # ================================================================================================
        # initial seed data
        # ================================================================================================
        # TODO: put the data inside an S3 bucket instead of a JSON string inside the lambda code
        populate_db_fn_handler = load_file(
            os.path.join(os.path.dirname(__file__), "../artefacts/functions/populate_db.py")
        )
        populate_db_fn = cdk.aws_lambda.Function(
            self,
            "PopulateDbFn",
            runtime=cdk.aws_lambda.Runtime.PYTHON_3_10,
            handler="index.insertMysfits",
            code=cdk.aws_lambda.Code.from_inline(code=populate_db_fn_handler),
            environment={
                "mysfitsTable": mysfits_table.table_name,
            },
        )
        mysfits_table.grant_read_write_data(populate_db_fn)

        # ================================================================================================
        # OUTPUTS
        # ================================================================================================

        cdk.CfnOutput(
            self,
            "ClicksBucketDestinationName",
            value=user_clicks_service.clicks_destination_bucket.bucket_name,
        )
        cdk.CfnOutput(
            self,
            "DeliveryStreamArn",
            value=user_clicks_service.mysfits_firehose_to_s3.attr_arn,
        )
        cdk.CfnOutput(
            self,
            "DeliveryStreamName",
            value=user_clicks_service.mysfits_firehose_to_s3.ref,
        )
        cdk.CfnOutput(
            self,
            "StreamProcessorFunctionName",
            value=user_clicks_service.mysfits_clicks_processor_fn.function_name,
        )
        cdk.CfnOutput(self, "PopulateDbFunctionName", value=populate_db_fn.function_name)
        cdk.CfnOutput(self, "MysfitsTableName", value=mysfits_table.table_name)
        cdk.CfnOutput(self, "UserClicksServiceAPIEndpoint", value=user_clicks_service.api.url)
        cdk.CfnOutput(self, "UserClicksServiceAPIId", value=user_clicks_service.api.rest_api_id)
