import os

import aws_cdk as cdk
import constructs

from localstack.utils.files import load_file


class ValidatorService(constructs.Construct):
    def __init__(
        self,
        scope: constructs.Construct,
        id: str,
        *,
        source,
        tokens_per_bucket,
        code_length,
        time_interval,
        event_bus,
        user_pool,
    ):
        super().__init__(scope, id)

        self.validator_table = validator_table = cdk.aws_dynamodb.Table(
            self,
            "ValidatorTable",
            table_name="serverlesspresso-validator-table",
            billing_mode=cdk.aws_dynamodb.BillingMode.PAY_PER_REQUEST,
            stream=cdk.aws_dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            partition_key=cdk.aws_dynamodb.Attribute(
                name="PK", type=cdk.aws_dynamodb.AttributeType.NUMBER
            ),
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        # GetQRcodeFunction GET /qr-code
        get_qr_code_fn_handler = load_file(
            os.path.join(os.path.dirname(__file__), "../artifacts/functions/getCode.js")
        )
        get_qr_code_fn = cdk.aws_lambda.Function(
            self,
            "GetQRcodeFunction",
            runtime=cdk.aws_lambda.Runtime.NODEJS_18_X,
            handler="index.handler",
            code=cdk.aws_lambda.Code.from_inline(code=get_qr_code_fn_handler),
            environment={
                "AWS_NODEJS_CONNECTION_REUSE_ENABLED": "1",
                "TableName": validator_table.table_name,
                "TimeInterval": time_interval,
                "CodeLength": code_length,
                "TokensPerBucket": tokens_per_bucket,
                "BusName": event_bus.event_bus_name,
                "Source": source,
            },
            timeout=cdk.Duration.seconds(15),
        )
        validator_table.grant_full_access(get_qr_code_fn)
        # VerifyQRcodeFunction POST /qr-code
        verify_qr_code_fn_handler = load_file(
            os.path.join(os.path.dirname(__file__), "../artifacts/functions/verifyCode.js")
        )
        verify_qr_code_fn = cdk.aws_lambda.Function(
            self,
            "VerifyQRcodeFunction",
            runtime=cdk.aws_lambda.Runtime.NODEJS_18_X,
            handler="index.handler",
            code=cdk.aws_lambda.Code.from_inline(code=verify_qr_code_fn_handler),
            environment={
                "AWS_NODEJS_CONNECTION_REUSE_ENABLED": "1",
                "TableName": validator_table.table_name,
                "TimeInterval": time_interval,
                "CodeLength": code_length,
                "TokensPerBucket": tokens_per_bucket,
                "BusName": event_bus.event_bus_name,
                "Source": source,
            },
            timeout=cdk.Duration.seconds(10),
        )
        validator_table.grant_full_access(verify_qr_code_fn)
        event_bus.grant_put_events_to(verify_qr_code_fn)

        # RESTApiValidatorService
        rest_api_validator_service = cdk.aws_apigateway.RestApi(
            self,
            "RESTApiValidatorService",
            default_cors_preflight_options=cdk.aws_apigateway.CorsOptions(
                allow_origins=["*"], allow_headers=["*"], allow_methods=["GET", "POST", "OPTIONS"]
            ),
        )
        # rest_api_validator_service.rest_api_id

        cognito_authorizer = cdk.aws_apigateway.CognitoUserPoolsAuthorizer(
            self, "MyCognitoAuthorizor", cognito_user_pools=[user_pool]
        )

        qr_code_resource = rest_api_validator_service.root.add_resource("qr-code")
        get_qr_code = qr_code_resource.add_method(
            "GET",
            authorization_type=cdk.aws_apigateway.AuthorizationType.COGNITO,
            authorization_scopes=["aws.cognito.signin.user.admin"],
            authorizer=cognito_authorizer,
            integration=cdk.aws_apigateway.LambdaIntegration(get_qr_code_fn),
        )
        verify_qr_code = qr_code_resource.add_method(
            "POST",
            authorization_type=cdk.aws_apigateway.AuthorizationType.COGNITO,
            authorization_scopes=["aws.cognito.signin.user.admin"],
            authorizer=cognito_authorizer,
            integration=cdk.aws_apigateway.LambdaIntegration(verify_qr_code_fn),
        )
