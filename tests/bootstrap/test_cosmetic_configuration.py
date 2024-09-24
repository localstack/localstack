import io
import os
from typing import Generator, Type
from urllib.parse import urlparse

import aws_cdk as cdk
import pytest
import requests
from botocore.exceptions import ClientError

from localstack import constants
from localstack.aws.connect import ServiceLevelClientFactory
from localstack.config import in_docker
from localstack.testing.pytest import markers
from localstack.testing.pytest.container import ContainerFactory, LogStreamFactory
from localstack.testing.scenario.cdk_lambda_helper import load_python_lambda_to_s3
from localstack.testing.scenario.provisioning import InfraProvisioner
from localstack.utils.bootstrap import ContainerConfigurators
from localstack.utils.net import get_free_tcp_port
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

pytestmarks = [
    pytest.mark.skipif(condition=in_docker(), reason="cannot run bootstrap tests in docker"),
    markers.aws.only_localstack,
]

STACK_NAME = "ClusterStack"
RESULT_KEY = "result"


@pytest.fixture(scope="class")
def port() -> int:
    return get_free_tcp_port()


@pytest.fixture(scope="class")
def chosen_localstack_host() -> str:
    """
    Choose a domain name that is guaranteed never to resolve, except by the LocalStack DNS server

    https://www.rfc-editor.org/rfc/rfc6761.html#section-6.4
    """
    return "foo.invalid"


# these fixtures have been copied from the pre-existing fixtures
@pytest.fixture(scope="class")
def class_container_factory() -> Generator[ContainerFactory, None, None]:
    factory = ContainerFactory()
    yield factory
    factory.remove_all_containers()


@pytest.fixture(scope="class")
def class_stream_container_logs() -> Generator[LogStreamFactory, None, None]:
    factory = LogStreamFactory()
    yield factory
    factory.close()


@pytest.fixture(scope="class", autouse=True)
def container(
    port,
    class_container_factory: ContainerFactory,
    class_stream_container_logs,
    wait_for_localstack_ready,
    chosen_localstack_host,
):
    ls_container = class_container_factory(
        configurators=[
            ContainerConfigurators.mount_localstack_volume(),
            ContainerConfigurators.debug,
            ContainerConfigurators.mount_docker_socket,
            ContainerConfigurators.gateway_listen(port),
            ContainerConfigurators.env_vars(
                {
                    "LOCALSTACK_HOST": chosen_localstack_host,
                }
            ),
        ]
    )
    with ls_container.start() as running_container:
        class_stream_container_logs(ls_container)
        wait_for_localstack_ready(running_container)
        yield running_container


def raise_exception_with_cloudwatch_logs(
    aws_client: ServiceLevelClientFactory, exc_class: Type[Exception] = AssertionError
):
    out = io.StringIO()

    log_group_names = [
        every["logGroupName"]
        for every in aws_client.logs.describe_log_groups(logGroupNamePrefix="/aws/lambda")[
            "logGroups"
        ]
    ]
    for name in log_group_names:
        print(f"Logs for {name}:", file=out)
        streams = [
            every["logStreamName"]
            for every in aws_client.logs.describe_log_streams(logGroupName=name)["logStreams"]
        ]
        for stream in streams:
            records = aws_client.logs.get_log_events(
                logGroupName=name,
                logStreamName=stream,
            )["events"]
            for record in records:
                print(record["message"], file=out)

    raise exc_class(out.getvalue())


class TestLocalStackHost:
    """
    Scenario test that runs LocalStack in a docker container with `LOCALSTACK_HOST` set to a
    non-default value. This ensures that setting the cosmetic "LOCALSTACK_HOST" does not affect
    the internal functionality of LocalStack.
    """

    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(
        self,
        aws_client_factory,
        infrastructure_setup,
        port,
        chosen_localstack_host,
        region_name,
    ):
        aws_client = aws_client_factory(
            endpoint_url=f"http://localhost:{port}",
            region_name=region_name,
        )

        infra: InfraProvisioner = infrastructure_setup(
            namespace="LocalStackHostBootstrap",
            port=port,
        )

        stack = cdk.Stack(infra.cdk_app, STACK_NAME)

        # results bucket
        results_bucket = cdk.aws_s3.Bucket(stack, "ResultsBucket")
        cdk.CfnOutput(stack, "ResultsBucketName", value=results_bucket.bucket_name)

        # assets bucket
        assets_bucket_name = "bootstrap-bucket"

        # OpenSearch domain
        domain_name = f"domain-{short_uid()}"
        domain = cdk.aws_opensearchservice.Domain(
            stack,
            "Domain",
            domain_name=domain_name,
            version=cdk.aws_opensearchservice.EngineVersion.OPENSEARCH_2_3,
        )
        cdk.CfnOutput(stack, "DomainEndpoint", value=domain.domain_endpoint)

        def create_lambda_function(
            stack: cdk.Stack,
            resource_name: str,
            resources_path: str,
            additional_packages: list[str] | None = None,
            runtime: cdk.aws_lambda.Runtime = cdk.aws_lambda.Runtime.PYTHON_3_10,
            environment: dict[str, str] | None = None,
            **kwargs,
        ) -> cdk.aws_lambda.Function:
            # needs to be deterministic so we can turn `infrastructure_setup(force_synth=True)` off
            key_name = f"fn-{resource_name.lower()}"
            assert os.path.isfile(resources_path), f"Cannot find function file {resources_path}"

            infra.add_custom_setup(
                lambda: load_python_lambda_to_s3(
                    s3_client=aws_client.s3,
                    bucket_name=assets_bucket_name,
                    key_name=key_name,
                    code_path=resources_path,
                    additional_python_packages=additional_packages or [],
                )
            )

            given_environment = environment or {}
            base_environment = {"CUSTOM_LOCALSTACK_HOSTNAME": chosen_localstack_host}
            full_environment = {**base_environment, **given_environment}
            return cdk.aws_lambda.Function(
                stack,
                resource_name,
                handler="index.handler",
                code=cdk.aws_lambda.S3Code(bucket=asset_bucket, key=key_name),
                runtime=runtime,
                environment=full_environment,
                **kwargs,
            )

        # SQS queue
        queue = cdk.aws_sqs.Queue(stack, "Queue")

        # SNS topic
        topic = cdk.aws_sns.Topic(stack, "Topic")
        topic.add_subscription(cdk.aws_sns_subscriptions.SqsSubscription(queue))

        # API Gateway
        asset_bucket = cdk.aws_s3.Bucket.from_bucket_name(
            stack,
            "BucketName",
            bucket_name=assets_bucket_name,
        )
        apigw_handler_fn = create_lambda_function(
            stack,
            resource_name="ApiHandlerFn",
            resources_path=os.path.join(os.path.dirname(__file__), "resources/apigw_handler.py"),
            environment={
                "TOPIC_ARN": topic.topic_arn,
            },
        )

        api = cdk.aws_apigateway.RestApi(stack, "RestApi")
        upload_url_resource = api.root.add_resource("upload")
        upload_url_resource.add_method(
            "POST", cdk.aws_apigateway.LambdaIntegration(apigw_handler_fn)
        )
        cdk.CfnOutput(stack, "ApiUrl", value=api.url)

        # event handler lambda
        create_lambda_function(
            stack,
            resource_name="EventHandlerFn",
            resources_path=os.path.join(os.path.dirname(__file__), "resources/event_handler.py"),
            additional_packages=["requests", "boto3"],
            events=[
                cdk.aws_lambda_event_sources.SqsEventSource(queue),
            ],
            environment={
                "DOMAIN_ENDPOINT": domain.domain_endpoint,
                "RESULTS_BUCKET": results_bucket.bucket_name,
                "RESULTS_KEY": RESULT_KEY,
            },
        )

        with infra.provisioner() as prov:
            yield prov

    def test_scenario(
        self, port, infrastructure, aws_client_factory, chosen_localstack_host, region_name
    ):
        """
        Scenario:
            * API Gateway handles web request
            * Broadcasts message onto SNS topic
            * Lambda subscribes via SQS and queries the OpenSearch domain health endpoint
        """
        # check cluster health endpoint

        aws_client = aws_client_factory(
            endpoint_url=f"http://localhost:{port}",
            region_name=region_name,
        )

        stack_outputs = infrastructure.get_stack_outputs(STACK_NAME)
        assert chosen_localstack_host in stack_outputs["DomainEndpoint"]
        health_url = stack_outputs["DomainEndpoint"].replace(
            chosen_localstack_host, constants.LOCALHOST_HOSTNAME
        )
        # we only have a route matcher for the domain with localstack_host in the URL,
        # but have to make the request against localhost so set the host header to the custom
        # domain and make the request against the rewritten domain
        host = urlparse(f"http://{stack_outputs['DomainEndpoint']}").hostname
        r = requests.get(f"http://{health_url}/_cluster/health", headers={"Host": host})
        r.raise_for_status()

        assert chosen_localstack_host in stack_outputs["ApiUrl"]
        api_url = (
            stack_outputs["ApiUrl"]
            .rstrip("/")
            .replace(chosen_localstack_host, constants.LOCALHOST_HOSTNAME)
        )

        url = f"{api_url}/upload"

        message = short_uid()
        r = requests.post(url, json={"message": message})
        r.raise_for_status()

        result_bucket = stack_outputs["ResultsBucketName"]

        def _is_result_file_ready():
            aws_client.s3.head_object(
                Bucket=result_bucket,
                Key=RESULT_KEY,
            )

        # wait a maximum of 10 seconds
        try:
            retry(_is_result_file_ready, retries=10)
        except ClientError as e:
            if "Not Found" not in str(e):
                raise

            # we could not find the file in S3 after the retry period, so fail the test with some
            # useful information
            raise_exception_with_cloudwatch_logs(aws_client)

        body = (
            aws_client.s3.get_object(Bucket=result_bucket, Key=RESULT_KEY)["Body"]
            .read()
            .decode("utf8")
        )
        assert body.strip() == message
