from pathlib import Path

from aws_cdk import CfnOutput, Duration, Stack
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lam
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_ssm as ssm
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks
from constructs import Construct


class CloudtrailTrackingStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # bucket to store logs
        bucket = s3.Bucket(self, "Bucket")

        # parameter storing the name of the bucket
        ssm.StringParameter(
            self,
            "bucketName",
            parameter_name="cloudtrail-bucket-name",
            string_value=bucket.bucket_name,
        )

        # lambda function handler for the stepfunction
        handler = lam.Function(
            self,
            "handler",
            runtime=lam.Runtime.PYTHON_3_9,
            handler="index.handler",
            code=lam.Code.from_asset(str(Path(__file__).parent.joinpath("handler"))),
            environment={
                "BUCKET": bucket.bucket_name,
            },
            timeout=Duration.seconds(60),
        )
        handler.add_to_role_policy(iam.PolicyStatement(actions=["cloudtrail:*"], resources=["*"]))
        bucket.grant_put(handler)

        # step function definition
        wait_step = sfn.Wait(self, "WaitStep", time=sfn.WaitTime.duration(Duration.seconds(300)))
        lambda_step = tasks.LambdaInvoke(self, "LambdaStep", lambda_function=handler)
        step_function = sfn.StateMachine(
            self, "StepFunction", definition=wait_step.next(lambda_step)
        )

        ssm.StringParameter(
            self,
            "stepFunctionArn",
            parameter_name="cloudtrail-stepfunction-arn",
            string_value=step_function.state_machine_arn,
        )
        CfnOutput(
            self,
            "stepFunctionArnOutput",
            value=step_function.state_machine_arn,
        )
        CfnOutput(
            self,
            "bucketNameOutput",
            value=bucket.bucket_name,
        )
