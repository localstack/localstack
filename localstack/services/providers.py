from localstack.aws.proxy import AwsApiListener
from localstack.services.moto import MotoFallbackDispatcher
from localstack.services.plugins import Service, aws_provider


@aws_provider()
def acm():
    from localstack.services.acm import acm_starter

    return Service("acm", start=acm_starter.start_acm)


@aws_provider()
def apigateway():
    from localstack.services.apigateway import apigateway_listener, apigateway_starter

    return Service(
        "apigateway",
        listener=apigateway_listener.UPDATE_APIGATEWAY,
        start=apigateway_starter.start_apigateway,
    )


@aws_provider()
def cloudformation():
    from localstack.services.cloudformation import cloudformation_starter

    return Service("cloudformation", start=cloudformation_starter.start_cloudformation)


@aws_provider(api="config")
def awsconfig():
    from localstack.services.configservice.provider import ConfigProvider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = ConfigProvider()
    return Service("config", listener=AwsApiListener("config", MotoFallbackDispatcher(provider)))


@aws_provider()
def cloudwatch():
    from localstack.services.cloudwatch.provider import CloudwatchProvider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = CloudwatchProvider()
    listener = AwsApiListener("cloudwatch", MotoFallbackDispatcher(provider))

    return Service(
        "cloudwatch",
        listener=listener,
        lifecycle_hook=provider,
    )


@aws_provider()
def dynamodb():
    from localstack.services.dynamodb import dynamodb_listener, dynamodb_starter

    return Service(
        "dynamodb",
        listener=dynamodb_listener.UPDATE_DYNAMODB,
        start=dynamodb_starter.start_dynamodb,
        check=dynamodb_starter.check_dynamodb,
    )


@aws_provider()
def dynamodbstreams():
    from localstack.aws.proxy import AwsApiListener
    from localstack.services.dynamodbstreams.provider import DynamoDBStreamsProvider

    provider = DynamoDBStreamsProvider()
    return Service(
        "dynamodbstreams",
        listener=AwsApiListener("dynamodbstreams", provider),
        lifecycle_hook=provider,
    )


@aws_provider()
def ec2():
    from localstack.services.ec2 import ec2_listener, ec2_starter

    return Service("ec2", listener=ec2_listener.UPDATE_EC2, start=ec2_starter.start_ec2)


@aws_provider()
def es():
    from localstack.aws.proxy import AwsApiListener
    from localstack.services.es.provider import EsProvider

    provider = EsProvider()
    return Service("es", listener=AwsApiListener("es", provider))


@aws_provider()
def firehose():
    from localstack.aws.proxy import AwsApiListener
    from localstack.services.firehose.provider import FirehoseProvider

    provider = FirehoseProvider()
    return Service("firehose", listener=AwsApiListener("firehose", provider))


@aws_provider()
def iam():
    from localstack.services.iam import iam_listener, iam_starter

    return Service("iam", listener=iam_listener.UPDATE_IAM, start=iam_starter.start_iam)


@aws_provider()
def sts():
    from localstack.services.sts import sts_listener, sts_starter

    return Service("sts", start=sts_starter.start_sts, listener=sts_listener.UPDATE_STS)


@aws_provider()
def kinesis():
    from localstack.services.kinesis import kinesis_listener, kinesis_starter

    return Service(
        "kinesis",
        listener=kinesis_listener.UPDATE_KINESIS,
        start=kinesis_starter.start_kinesis,
        check=kinesis_starter.check_kinesis,
    )


@aws_provider()
def kms():
    from localstack.services.kms import kms_listener, kms_starter

    return Service("kms", listener=kms_listener.UPDATE_KMS, start=kms_starter.start_kms)


@aws_provider(api="lambda")
def awslambda():
    from localstack.services.awslambda import lambda_starter

    return Service(
        "lambda",
        start=lambda_starter.start_lambda,
        stop=lambda_starter.stop_lambda,
        check=lambda_starter.check_lambda,
    )


@aws_provider()
def logs():
    from localstack.services.logs import logs_listener, logs_starter

    return Service(
        "logs", listener=logs_listener.UPDATE_LOGS, start=logs_starter.start_cloudwatch_logs
    )


@aws_provider()
def opensearch():
    from localstack.aws.proxy import AwsApiListener
    from localstack.services.opensearch.provider import OpensearchProvider

    provider = OpensearchProvider()
    return Service("opensearch", listener=AwsApiListener("opensearch", provider))


@aws_provider()
def redshift():
    from localstack.services.redshift.provider import RedshiftProvider

    provider = RedshiftProvider()
    listener = AwsApiListener("redshift", MotoFallbackDispatcher(provider))

    return Service("redshift", listener=listener)


@aws_provider()
def route53():
    from localstack.services.route53 import route53_listener, route53_starter

    return Service(
        "route53", listener=route53_listener.UPDATE_ROUTE53, start=route53_starter.start_route53
    )


@aws_provider()
def route53resolver():
    from localstack.services.route53 import route53_starter

    return Service("route53resolver", start=route53_starter.start_route53_resolver)


@aws_provider()
def s3():
    from localstack.services.s3 import s3_listener, s3_starter

    return Service(
        "s3", listener=s3_listener.UPDATE_S3, start=s3_starter.start_s3, check=s3_starter.check_s3
    )


@aws_provider()
def secretsmanager():
    from localstack.services.secretsmanager import secretsmanager_listener, secretsmanager_starter

    return Service(
        "secretsmanager",
        listener=secretsmanager_listener.UPDATE_SECRETSMANAGER,
        start=secretsmanager_starter.start_secretsmanager,
        check=secretsmanager_starter.check_secretsmanager,
    )


@aws_provider()
def ses():
    from localstack.services.ses import ses_listener, ses_starter

    return Service("ses", listener=ses_listener.UPDATE_SES, start=ses_starter.start_ses)


@aws_provider()
def sns():
    from localstack.services.sns import sns_listener, sns_starter

    return Service("sns", listener=sns_listener.UPDATE_SNS, start=sns_starter.start_sns)


@aws_provider()
def sqs():
    from localstack.services.sqs import sqs_listener, sqs_starter

    return Service(
        "sqs",
        listener=sqs_listener.UPDATE_SQS,
        start=sqs_starter.start_sqs,
        check=sqs_starter.check_sqs,
    )


@aws_provider(api="sqs", name="asf")
def sqs_asf():
    from localstack.aws.proxy import AwsApiListener
    from localstack.services.sqs.provider import SqsProvider

    provider = SqsProvider()

    return Service("sqs", listener=AwsApiListener("sqs", provider), lifecycle_hook=provider)


@aws_provider()
def ssm():
    from localstack.services.ssm import ssm_listener, ssm_starter

    return Service("ssm", listener=ssm_listener.UPDATE_SSM, start=ssm_starter.start_ssm)


@aws_provider()
def events():
    from localstack.services.events import events_listener, events_starter

    return Service(
        "events", listener=events_listener.UPDATE_EVENTS, start=events_starter.start_events
    )


@aws_provider()
def stepfunctions():
    from localstack.services.stepfunctions import stepfunctions_listener, stepfunctions_starter

    return Service(
        "stepfunctions",
        listener=stepfunctions_listener.UPDATE_STEPFUNCTIONS,
        start=stepfunctions_starter.start_stepfunctions,
        check=stepfunctions_starter.check_stepfunctions,
    )


@aws_provider()
def swf():
    from localstack.services.swf import swf_starter

    return Service(
        "swf",
        start=swf_starter.start_swf,
    )


@aws_provider()
def resourcegroupstaggingapi():
    from localstack.services.resourcegroupstaggingapi import rgta_listener, rgta_starter

    return Service(
        "resourcegroupstaggingapi",
        listener=rgta_listener.UPDATE_RGSA,
        start=rgta_starter.start_rgsa,
    )


@aws_provider(api="resource-groups")
def resource_groups():
    from localstack.services.resourcegroups import rg_listener, rg_starter

    return Service("resource-groups", listener=rg_listener.UPDATE_RG, start=rg_starter.start_rg)


@aws_provider()
def support():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.support.provider import SupportProvider

    provider = SupportProvider()
    return Service(
        "support",
        listener=AwsApiListener("support", MotoFallbackDispatcher(provider)),
    )
