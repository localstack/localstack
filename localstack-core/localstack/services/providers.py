from localstack.aws.forwarder import HttpFallbackDispatcher
from localstack.services.plugins import (
    Service,
    aws_provider,
)


@aws_provider()
def acm():
    from localstack.services.acm.provider import AcmProvider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = AcmProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="apigateway")
def apigateway():
    from localstack.services.apigateway.legacy.provider import ApigatewayProvider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = ApigatewayProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="apigateway", name="next_gen")
def apigateway_next_gen():
    from localstack.services.apigateway.next_gen.provider import ApigatewayNextGenProvider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = ApigatewayNextGenProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def cloudformation():
    from localstack.services.cloudformation.provider import CloudformationProvider

    provider = CloudformationProvider()
    return Service.for_provider(provider)


@aws_provider(api="config")
def awsconfig():
    from localstack.services.configservice.provider import ConfigProvider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = ConfigProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="cloudwatch", name="default")
def cloudwatch():
    from localstack.services.cloudwatch.provider_v2 import CloudwatchProvider

    provider = CloudwatchProvider()
    return Service.for_provider(provider)


@aws_provider(api="cloudwatch", name="v1")
def cloudwatch_v1():
    from localstack.services.cloudwatch.provider import CloudwatchProvider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = CloudwatchProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="cloudwatch", name="v2")
def cloudwatch_v2():
    from localstack.services.cloudwatch.provider_v2 import CloudwatchProvider

    provider = CloudwatchProvider()
    return Service.for_provider(provider)


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


@aws_provider(api="dynamodbstreams", name="v2")
def dynamodbstreams_v2():
    from localstack.services.dynamodbstreams.v2.provider import DynamoDBStreamsProvider

    provider = DynamoDBStreamsProvider()
    return Service.for_provider(provider)


@aws_provider(api="dynamodb", name="v2")
def dynamodb_v2():
    from localstack.services.dynamodb.v2.provider import DynamoDBProvider

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
    from localstack.services.moto import MotoFallbackDispatcher

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
    from localstack.services.moto import MotoFallbackDispatcher
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
    from localstack.services.kms.provider import KmsProvider

    provider = KmsProvider()
    return Service.for_provider(provider)


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
    from localstack.services.moto import MotoFallbackDispatcher

    provider = LogsProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def opensearch():
    from localstack.services.opensearch.provider import OpensearchProvider

    provider = OpensearchProvider()
    return Service.for_provider(provider)


@aws_provider()
def redshift():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.redshift.provider import RedshiftProvider

    provider = RedshiftProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def route53():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.route53.provider import Route53Provider

    provider = Route53Provider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def route53resolver():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.route53resolver.provider import Route53ResolverProvider

    provider = Route53ResolverProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="s3", name="asf")
def s3_asf():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.s3.legacy.provider import S3Provider

    provider = S3Provider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="s3", name="v2")
def s3_v2():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.s3.legacy.provider import S3Provider

    provider = S3Provider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="s3", name="legacy_v2")
def s3_legacy_v2():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.s3.legacy.provider import S3Provider

    provider = S3Provider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="s3", name="default")
def s3():
    from localstack.services.s3.provider import S3Provider

    provider = S3Provider()
    return Service.for_provider(provider)


@aws_provider(api="s3", name="stream")
def s3_stream():
    from localstack.services.s3.provider import S3Provider

    provider = S3Provider()
    return Service.for_provider(provider)


@aws_provider(api="s3", name="v3")
def s3_v3():
    from localstack.services.s3.provider import S3Provider

    provider = S3Provider()
    return Service.for_provider(provider)


@aws_provider()
def s3control():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.s3control.provider import S3ControlProvider

    provider = S3ControlProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def scheduler():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.scheduler.provider import SchedulerProvider

    provider = SchedulerProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def secretsmanager():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.secretsmanager.provider import SecretsmanagerProvider

    provider = SecretsmanagerProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def ses():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.ses.provider import SesProvider

    provider = SesProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def sns():
    from localstack.services.moto import MotoFallbackDispatcher
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
    return Service.for_provider(provider)


@aws_provider()
def ssm():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.ssm.provider import SsmProvider

    provider = SsmProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="events", name="default")
def events():
    from localstack.services.events.v1.provider import EventsProvider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = EventsProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="events", name="v1")
def events_v1():
    from localstack.services.events.v1.provider import EventsProvider
    from localstack.services.moto import MotoFallbackDispatcher

    provider = EventsProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="events", name="v2")
def events_v2():
    from localstack.services.events.provider import EventsProvider

    provider = EventsProvider()
    return Service.for_provider(provider)


@aws_provider()
def stepfunctions():
    from localstack.services.stepfunctions.provider import StepFunctionsProvider

    provider = StepFunctionsProvider()
    return Service.for_provider(provider)


@aws_provider(api="stepfunctions", name="v2")
def stepfunctions_v2():
    from localstack.services.stepfunctions.provider import StepFunctionsProvider

    provider = StepFunctionsProvider()
    return Service.for_provider(provider)


@aws_provider(api="stepfunctions", name="v1")
def stepfunctions_legacy():
    from localstack.services.stepfunctions.legacy.provider_legacy import StepFunctionsProvider

    provider = StepFunctionsProvider()
    return Service.for_provider(
        provider,
        dispatch_table_factory=lambda _provider: HttpFallbackDispatcher(
            _provider, _provider.get_forward_url
        ),
    )


@aws_provider(api="stepfunctions", name="legacy")
def stepfunctions_v1():
    from localstack.services.stepfunctions.legacy.provider_legacy import StepFunctionsProvider

    provider = StepFunctionsProvider()
    return Service.for_provider(
        provider,
        dispatch_table_factory=lambda _provider: HttpFallbackDispatcher(
            _provider, _provider.get_forward_url
        ),
    )


@aws_provider()
def swf():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.swf.provider import SWFProvider

    provider = SWFProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def resourcegroupstaggingapi():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.resourcegroupstaggingapi.provider import (
        ResourcegroupstaggingapiProvider,
    )

    provider = ResourcegroupstaggingapiProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="resource-groups")
def resource_groups():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.resource_groups.provider import ResourceGroupsProvider

    provider = ResourceGroupsProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def support():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.support.provider import SupportProvider

    provider = SupportProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def transcribe():
    from localstack.services.moto import MotoFallbackDispatcher
    from localstack.services.transcribe.provider import TranscribeProvider

    provider = TranscribeProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)
