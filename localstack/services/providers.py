from localstack import config
from localstack.aws.proxy import AwsApiListener
from localstack.services.moto import MotoFallbackDispatcher
from localstack.services.plugins import Service, aws_provider


@aws_provider()
def acm():
    from localstack.services.acm.provider import AcmProvider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = AcmProvider()

    return Service("acm", listener=AwsApiListener("acm", MotoFallbackDispatcher(provider)))


@aws_provider()
def apigateway():
    from localstack.services.apigateway.provider import ApigatewayApiListener, ApigatewayProvider

    provider = ApigatewayProvider()
    listener = ApigatewayApiListener("apigateway", MotoFallbackDispatcher(provider))

    return Service("apigateway", listener=listener, lifecycle_hook=provider)


@aws_provider()
def cloudformation():
    from localstack.services.cloudformation.provider import CloudformationProvider

    provider = CloudformationProvider()

    return Service("cloudformation", listener=AwsApiListener("cloudformation", provider))


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
    from localstack.services.dynamodb.provider import DynamoDBApiListener

    listener = DynamoDBApiListener()
    return Service(
        "dynamodb",
        listener=listener,
        lifecycle_hook=listener.provider,
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
    from localstack.services.ec2.provider import Ec2Provider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = Ec2Provider()
    return Service(
        "ec2",
        listener=AwsApiListener("ec2", MotoFallbackDispatcher(provider)),
    )


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
    from localstack.services.iam.provider import IamProvider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = IamProvider()
    return Service(
        "iam",
        listener=AwsApiListener("iam", MotoFallbackDispatcher(provider)),
    )


@aws_provider()
def sts():
    from localstack.services.sts.provider import StsAwsApiListener

    listener = StsAwsApiListener()
    return Service("sts", listener=listener)


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
    if config.KMS_PROVIDER == "local-kms":
        from localstack.services.kms import kms_starter

        return Service("kms", start=kms_starter.start_kms_local)

    # fall back to default provider
    from localstack.services.kms.provider import KmsProvider

    provider = KmsProvider()
    return Service("kms", listener=AwsApiListener("kms", MotoFallbackDispatcher(provider)))


@aws_provider(api="lambda")
def awslambda():
    from localstack.services.awslambda import lambda_starter

    return Service(
        "lambda",
        start=lambda_starter.start_lambda,
        stop=lambda_starter.stop_lambda,
        check=lambda_starter.check_lambda,
    )


@aws_provider(api="lambda", name="asf")
def awslambda_asf():
    from localstack.aws.proxy import AwsApiListener
    from localstack.services.awslambda.provider import LambdaProvider

    provider = LambdaProvider()

    return Service("lambda", listener=AwsApiListener("lambda", provider), lifecycle_hook=provider)


@aws_provider()
def logs():
    from localstack.services.logs.provider import LogsAwsApiListener

    listener = LogsAwsApiListener()
    return Service("logs", listener=listener)


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
    from localstack.services.route53.provider import Route53Provider

    provider = Route53Provider()

    return Service("route53", listener=AwsApiListener("route53", MotoFallbackDispatcher(provider)))


@aws_provider()
def route53resolver():
    from localstack.services.route53.provider import Route53ResolverApi

    provider = Route53ResolverApi()

    return Service(
        "route53resolver",
        listener=AwsApiListener("route53resolver", MotoFallbackDispatcher(provider)),
    )


@aws_provider()
def s3():
    from localstack.services.s3 import s3_listener, s3_starter

    return Service(
        "s3", listener=s3_listener.UPDATE_S3, start=s3_starter.start_s3, check=s3_starter.check_s3
    )


@aws_provider()
def s3control():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.s3control.provider import S3ControlProvider

    provider = S3ControlProvider()
    return Service(
        "s3control", listener=AwsApiListener("s3control", MotoFallbackDispatcher(provider))
    )


@aws_provider()
def secretsmanager():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.secretsmanager.provider import SecretsmanagerProvider

    provider = SecretsmanagerProvider()
    return Service(
        "secretsmanager",
        listener=AwsApiListener("secretsmanager", MotoFallbackDispatcher(provider)),
    )


@aws_provider()
def ses():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.ses.provider import SesProvider

    provider = SesProvider()
    return Service(
        "ses",
        listener=AwsApiListener("ses", MotoFallbackDispatcher(provider)),
        lifecycle_hook=provider,
    )


@aws_provider()
def sns():
    from localstack.aws.proxy import AwsApiListener
    from localstack.services.sns.provider import SnsProvider

    provider = SnsProvider()

    return Service("sns", listener=AwsApiListener("sns", provider), lifecycle_hook=provider)


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
    from localstack.services import edge
    from localstack.services.sqs import query_api
    from localstack.services.sqs.provider import SqsProvider

    query_api.register(edge.ROUTER)

    provider = SqsProvider()

    return Service("sqs", listener=AwsApiListener("sqs", provider), lifecycle_hook=provider)


@aws_provider()
def ssm():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.ssm.provider import SsmProvider

    provider = SsmProvider()
    return Service(
        "ssm",
        listener=AwsApiListener("ssm", MotoFallbackDispatcher(provider)),
    )


@aws_provider()
def events():
    from localstack.services.events.provider import EventsProvider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = EventsProvider()
    return Service(
        "events",
        listener=AwsApiListener("events", MotoFallbackDispatcher(provider)),
    )


@aws_provider()
def stepfunctions():
    from localstack.services.stepfunctions.provider import StepFunctionsApiListener

    listener = StepFunctionsApiListener()
    return Service(
        "stepfunctions",
        listener=listener,
        lifecycle_hook=listener.provider,
    )


@aws_provider()
def swf():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.swf.provider import SWFProvider

    provider = SWFProvider()
    return Service(
        "swf",
        listener=AwsApiListener("swf", MotoFallbackDispatcher(provider)),
    )


@aws_provider()
def resourcegroupstaggingapi():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.resourcegroupstaggingapi.provider import (
        ResourcegroupstaggingapiProvider,
    )

    provider = ResourcegroupstaggingapiProvider()
    return Service(
        "resourcegroupstaggingapi",
        listener=AwsApiListener("resourcegroupstaggingapi", MotoFallbackDispatcher(provider)),
    )


@aws_provider(api="resource-groups")
def resource_groups():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.resourcegroups.provider import ResourceGroupsProvider

    provider = ResourceGroupsProvider()
    return Service(
        "resource-groups",
        listener=AwsApiListener("resource-groups", MotoFallbackDispatcher(provider)),
    )


@aws_provider()
def support():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.support.provider import SupportProvider

    provider = SupportProvider()
    return Service(
        "support",
        listener=AwsApiListener("support", MotoFallbackDispatcher(provider)),
    )
