import json
import os

import aws_cdk as cdk
import aws_cdk.aws_apigateway as apigw
import aws_cdk.aws_dynamodb as dynamodb
import aws_cdk.aws_iam as iam
import aws_cdk.aws_lambda as lambda_
import aws_cdk.aws_s3 as s3
import constructs

from localstack.utils.files import load_file


class UserClicksService(constructs.Construct):
    def __init__(
        self,
        scope: constructs.Construct,
        id: str,
        *,
        account_id: str,
        mysfits_table: dynamodb.Table
    ):
        super().__init__(scope, id)
        # TODO: the bucket is versioned in the sample, but not sure why?
        self.clicks_destination_bucket = s3.Bucket(
            self,
            "ClicksBucketDestination",
            # versioned=True,  # in the sample the bucket is versioned but it seems just trickier to clean up for no real gain?
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        # We could use the table to .grant_read_data instead but that's what the sample does
        lambda_function_policy = iam.PolicyStatement()
        lambda_function_policy.add_actions("dynamodb:GetItem")
        lambda_function_policy.add_resources(mysfits_table.table_arn)

        mysfits_clicks_processor_fn_handler = load_file(
            os.path.join(os.path.dirname(__file__), "../artefacts/functions/stream_processor.py")
        )
        self.mysfits_clicks_processor_fn = lambda_.Function(
            self,
            "StreamProcessorFunction",
            handler="index.processRecord",
            runtime=lambda_.Runtime.PYTHON_3_10,
            description="An Amazon Kinesis Firehose stream processor that enriches click records to not just include a mysfitId, but also other attributes that can be analyzed later.",
            memory_size=128,
            code=lambda_.Code.from_inline(code=mysfits_clicks_processor_fn_handler),
            initial_policy=[lambda_function_policy],
            environment={
                "MYSFITS_TABLE_NAME": mysfits_table.table_name,
            },
            timeout=cdk.Duration.seconds(30),
        )

        firehose_delivery_role = iam.Role(
            self,
            "FirehoseDeliveryRole",
            role_name="FirehoseDeliveryRole",
            assumed_by=iam.ServicePrincipal("firehose.amazonaws.com"),
            external_ids=[account_id],
        )

        firehose_delivery_policy_s3_stmt = iam.PolicyStatement()
        firehose_delivery_policy_s3_stmt.add_actions(
            "s3:AbortMultipartUpload",
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:ListBucketMultipartUploads",
            "s3:PutObject",
        )
        firehose_delivery_policy_s3_stmt.add_resources(self.clicks_destination_bucket.bucket_arn)
        firehose_delivery_policy_s3_stmt.add_resources(
            self.clicks_destination_bucket.arn_for_objects("*")
        )

        firehose_delivery_policy_lambda_stmt = iam.PolicyStatement()
        firehose_delivery_policy_lambda_stmt.add_actions("lambda:InvokeFunction")
        firehose_delivery_policy_lambda_stmt.add_resources(
            self.mysfits_clicks_processor_fn.function_arn
        )

        firehose_delivery_role.add_to_policy(firehose_delivery_policy_s3_stmt)
        firehose_delivery_role.add_to_policy(firehose_delivery_policy_lambda_stmt)

        # TODO: check the alpha library for KinesisFirehose DeliveryStream
        self.mysfits_firehose_to_s3 = cdk.aws_kinesisfirehose.CfnDeliveryStream(
            self,
            "DeliveryStream",
            extended_s3_destination_configuration={
                "bucketArn": self.clicks_destination_bucket.bucket_arn,
                "bufferingHints": {
                    "intervalInSeconds": 60,
                    "sizeInMBs": 50,
                },
                "compressionFormat": "UNCOMPRESSED",
                "prefix": "firehose/",
                "roleArn": firehose_delivery_role.role_arn,
                "processingConfiguration": {
                    "enabled": True,
                    "processors": [
                        {
                            "parameters": [
                                {
                                    "parameterName": "LambdaArn",
                                    "parameterValue": self.mysfits_clicks_processor_fn.function_arn,
                                }
                            ],
                            "type": "Lambda",
                        }
                    ],
                },
            },
        )
        self.mysfits_clicks_processor_fn.add_permission(
            "LambdaPermission",
            action="lambda:InvokeFunction",
            principal=iam.ServicePrincipal("firehose.amazonaws.com"),
            source_account=account_id,
            source_arn=self.mysfits_firehose_to_s3.attr_arn,
        )

        click_processing_api_role = iam.Role(
            self,
            "ClickProcessingApiRole",
            assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"),
        )
        api_policy = iam.PolicyStatement()
        api_policy.add_actions("firehose:PutRecord")
        api_policy.add_resources(self.mysfits_firehose_to_s3.attr_arn)
        iam.Policy(
            self,
            "ClickProcessingApiPolicy",
            policy_name="api_gateway_firehose_proxy_role",
            statements=[api_policy],
            roles=[click_processing_api_role],
        )

        self.api = apigw.RestApi(
            self,
            "APIEndpoint",
            rest_api_name="ClickProcessing API Service",
            endpoint_types=[apigw.EndpointType.REGIONAL],
            cloud_watch_role_removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        clicks = self.api.root.add_resource("clicks")

        clicks.add_method(
            "PUT",
            integration=apigw.AwsIntegration(
                service="firehose",
                integration_http_method="POST",
                action="PutRecord",
                options=apigw.IntegrationOptions(
                    connection_type=apigw.ConnectionType.INTERNET,
                    credentials_role=click_processing_api_role,
                    integration_responses=[
                        apigw.IntegrationResponse(
                            status_code="200",
                            response_templates={"application/json": '{"status":"OK"}'},
                            response_parameters={
                                "method.response.header.Access-Control-Allow-Headers": "'Content-Type'",
                                "method.response.header.Access-Control-Allow-Methods": "'OPTIONS,PUT'",
                                "method.response.header.Access-Control-Allow-Origin": "'*'",
                            },
                        )
                    ],
                    request_parameters={
                        "integration.request.header.Content-Type": "'application/x-amz-json-1.1'"
                    },
                    request_templates={
                        "application/json": json.dumps(
                            {
                                "DeliveryStreamName": self.mysfits_firehose_to_s3.ref,
                                "Record": {"Data": "$util.base64Encode($input.json('$'))"},
                            }
                        )
                    },
                ),
            ),
            method_responses=[
                apigw.MethodResponse(
                    status_code="200",
                    response_parameters={
                        "method.response.header.Access-Control-Allow-Headers": True,
                        "method.response.header.Access-Control-Allow-Methods": True,
                        "method.response.header.Access-Control-Allow-Origin": True,
                    },
                )
            ],
        )

        clicks.add_method(
            "OPTIONS",
            integration=apigw.MockIntegration(
                integration_responses=[
                    apigw.IntegrationResponse(
                        status_code="200",
                        response_parameters={
                            "method.response.header.Access-Control-Allow-Headers": "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent'",
                            "method.response.header.Access-Control-Allow-Origin": "'*'",
                            "method.response.header.Access-Control-Allow-Credentials": "'false'",
                            "method.response.header.Access-Control-Allow-Methods": "'OPTIONS,GET,PUT,POST,DELETE'",
                        },
                    )
                ],
                passthrough_behavior=apigw.PassthroughBehavior.NEVER,
                request_templates={"application/json": '{"statusCode": 200}'},
            ),
            method_responses=[
                apigw.MethodResponse(
                    status_code="200",
                    response_parameters={
                        "method.response.header.Access-Control-Allow-Headers": True,
                        "method.response.header.Access-Control-Allow-Methods": True,
                        "method.response.header.Access-Control-Allow-Credentials": True,
                        "method.response.header.Access-Control-Allow-Origin": True,
                    },
                )
            ],
        )
