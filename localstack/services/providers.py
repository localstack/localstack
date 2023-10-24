from localstack import config
from localstack.aws.forwarder import HttpFallbackDispatcher
from localstack.services.moto import MotoFallbackDispatcher
from localstack.services.plugins import Service, aws_provider


@aws_provider()
def acm():
    from localstack.services.acm.provider import AcmProvider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = AcmProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="apigateway")
def apigateway():
    from localstack.services.apigateway.provider import ApigatewayProvider

    provider = ApigatewayProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def cloudformation():
    from localstack.services.cloudformation.provider import CloudformationProvider

    provider = CloudformationProvider()
    return Service.for_provider(provider)


@aws_provider(api="config")
def awsconfig():
    from localstack.services.configservice.provider import ConfigProvider

    provider = ConfigProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def cloudwatch():
    from localstack.services.cloudwatch.provider import CloudwatchProvider

    provider = CloudwatchProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def dynamodb():
    from localstack.services.dynamodb.provider import DynamoDBProvider

    provider = DynamoDBProvider()
    return Service.for_provider(
        provider,
        dispatch_table_factory=lambda _provider: HttpFallbackDispatcher(
            _provider, _provider.get_forward_url
        ),
    )


@aws_provider()
def dynamodbstreams():
    from localstack.services.dynamodbstreams.provider import DynamoDBStreamsProvider

    provider = DynamoDBStreamsProvider()
    return Service.for_provider(provider)


@aws_provider()
def ec2():
    from localstack.services.ec2.provider import Ec2Provider

    provider = Ec2Provider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def es():
    from localstack.services.es.provider import EsProvider

    provider = EsProvider()
    return Service.for_provider(provider)


@aws_provider()
def firehose():
    from localstack.services.firehose.provider import FirehoseProvider

    provider = FirehoseProvider()
    return Service.for_provider(provider)


@aws_provider()
def iam():
    from localstack.services.iam.provider import IamProvider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = IamProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def sts():
    from localstack.services.sts.provider import StsProvider

    provider = StsProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def kinesis():
    from localstack.services.kinesis.provider import KinesisProvider

    provider = KinesisProvider()
    return Service.for_provider(
        provider,
        dispatch_table_factory=lambda _provider: HttpFallbackDispatcher(
            _provider, _provider.get_forward_url
        ),
    )


@aws_provider()
def kms():
    if config.KMS_PROVIDER == "local-kms":
        from localstack.services.kms.local_kms_provider import LocalKmsProvider

        provider = LocalKmsProvider()
        return Service.for_provider(
            provider,
            dispatch_table_factory=lambda _provider: HttpFallbackDispatcher(
                _provider, _provider.start_and_get_backend
            ),
        )

    from localstack.services.kms.provider import KmsProvider

    provider = KmsProvider()
    return Service.for_provider(provider)


@aws_provider(api="lambda", name="legacy")
def lambda_legacy():
    from localstack.services.lambda_ import lambda_starter

    return Service(
        "lambda",
        start=lambda_starter.start_lambda,
        stop=lambda_starter.stop_lambda,
        check=lambda_starter.check_lambda,
        lifecycle_hook=lambda_starter.LambdaLifecycleHook(),
    )


@aws_provider(api="lambda", name="v1")
def lambda_v1():
    from localstack.services.lambda_ import lambda_starter

    return Service(
        "lambda",
        start=lambda_starter.start_lambda,
        stop=lambda_starter.stop_lambda,
        check=lambda_starter.check_lambda,
        lifecycle_hook=lambda_starter.LambdaLifecycleHook(),
    )


@aws_provider(api="lambda")
def lambda_():
    from localstack.services.lambda_.provider import LambdaProvider

    provider = LambdaProvider()
    return Service.for_provider(provider)


@aws_provider(api="lambda", name="asf")
def lambda_asf():
    from localstack.services.lambda_.provider import LambdaProvider

    provider = LambdaProvider()
    return Service.for_provider(provider)


@aws_provider(api="lambda", name="v2")
def lambda_v2():
    from localstack.services.lambda_.provider import LambdaProvider

    provider = LambdaProvider()
    return Service.for_provider(provider)


@aws_provider()
def logs():
    from localstack.services.logs.provider import LogsProvider

    provider = LogsProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def opensearch():
    from localstack.services.opensearch.provider import OpensearchProvider

    provider = OpensearchProvider()
    return Service.for_provider(provider)


@aws_provider()
def ram():
    from localstack.services.ram.provider import RamProvider

    provider = RamProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def redshift():
    from localstack.services.redshift.provider import RedshiftProvider

    provider = RedshiftProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def route53():
    from localstack.services.route53.provider import Route53Provider

    provider = Route53Provider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def route53resolver():
    from localstack.services.route53resolver.provider import Route53ResolverProvider

    provider = Route53ResolverProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="s3", name="asf")
def s3_asf():
    from localstack.services.s3.provider import S3Provider

    provider = S3Provider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="s3", name="default")
def s3():
    from localstack.services.s3.provider import S3Provider

    provider = S3Provider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="s3", name="v2")
def s3_v2():
    from localstack.services.s3.provider import S3Provider

    provider = S3Provider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="s3", name="stream")
def s3_stream():
    from localstack.services.s3.v3.provider import S3Provider

    provider = S3Provider()
    return Service.for_provider(provider)


@aws_provider(api="s3", name="v3")
def s3_v3():
    from localstack.services.s3.v3.provider import S3Provider

    provider = S3Provider()
    return Service.for_provider(provider)


@aws_provider()
def s3control():
    from localstack.services.s3control.provider import S3ControlProvider

    provider = S3ControlProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def scheduler():
    from localstack.services.scheduler.provider import SchedulerProvider

    provider = SchedulerProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def secretsmanager():
    from localstack.services.secretsmanager.provider import SecretsmanagerProvider

    provider = SecretsmanagerProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def ses():
    from localstack.services.ses.provider import SesProvider

    provider = SesProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def sns():
    from localstack.services.sns.provider import SnsProvider

    provider = SnsProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def sqs():
    from localstack.services import edge
    from localstack.services.sqs import query_api
    from localstack.services.sqs.provider import SqsProvider

    query_api.register(edge.ROUTER)

    provider = SqsProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def ssm():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.ssm.provider import SsmProvider

    provider = SsmProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def events():
    from localstack.services.events.provider import EventsProvider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = EventsProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def stepfunctions():
    from localstack.services.stepfunctions.provider import StepFunctionsProvider

    provider = StepFunctionsProvider()
    return Service.for_provider(
        provider,
        dispatch_table_factory=lambda _provider: HttpFallbackDispatcher(
            _provider, _provider.get_forward_url
        ),
    )


@aws_provider(api="stepfunctions", name="v1")
def stepfunctions_v1():
    from localstack.services.stepfunctions.provider import StepFunctionsProvider

    provider = StepFunctionsProvider()
    return Service.for_provider(
        provider,
        dispatch_table_factory=lambda _provider: HttpFallbackDispatcher(
            _provider, _provider.get_forward_url
        ),
    )


@aws_provider(api="stepfunctions", name="v2")
def stepfunctions_v2():
    from localstack.services.stepfunctions.provider_v2 import StepFunctionsProvider

    provider = StepFunctionsProvider()
    return Service.for_provider(provider)


@aws_provider()
def swf():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.swf.provider import SWFProvider

    provider = SWFProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def resourcegroupstaggingapi():
    from localstack.services.resourcegroupstaggingapi.provider import (
        ResourcegroupstaggingapiProvider,
    )

    provider = ResourcegroupstaggingapiProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="resource-groups")
def resource_groups():
    from localstack.services.resource_groups.provider import ResourceGroupsProvider

    provider = ResourceGroupsProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def support():
    from localstack.services.support.provider import SupportProvider

    provider = SupportProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def transcribe():
    from localstack.services.transcribe.provider import TranscribeProvider

    provider = TranscribeProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)
