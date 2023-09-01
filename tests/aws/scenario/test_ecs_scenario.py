import aws_cdk as cdk
import aws_cdk.aws_ecs as ecs
import pytest
import requests

from localstack.testing.pytest import markers
from localstack.testing.scenario.provisioning import InfraProvisioner


@pytest.mark.skip(
    reason="requires pro",
)
@markers.acceptance_test_beta
class TestEcsScenario:
    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client):
        app = cdk.App()
        stack = cdk.Stack(app, "ClusterStack")
        nginx_service = cdk.aws_ecs_patterns.ApplicationLoadBalancedFargateService(
            stack,
            "NginxService",
            task_image_options=cdk.aws_ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                image=ecs.ContainerImage.from_registry("nginx"),
                container_port=80,
            ),
            desired_count=1,
            listener_port=8080,  # TODO: this doesn't seem to be working yet
        )
        cdk.CfnOutput(stack, "ClusterName", value=nginx_service.cluster.cluster_name)
        cdk.CfnOutput(stack, "ServiceName", value=nginx_service.service.service_name)
        cdk.CfnOutput(stack, "AlbArn", value=nginx_service.load_balancer.load_balancer_arn)

        provisioner = InfraProvisioner(aws_client)
        provisioner.add_cdk_stack(stack)
        with provisioner.provisioner() as prov:
            yield prov

    @markers.aws.unknown
    def test_scenario_validate_infra(self, aws_client, infrastructure):
        outputs = infrastructure.get_stack_outputs(stack_name="ClusterStack")
        cluster_name = outputs["ClusterName"]
        alb_arn = outputs["AlbArn"]
        clusters = aws_client.ecs.describe_clusters(clusters=[cluster_name])
        assert clusters["clusters"][0]["clusterName"] == cluster_name

        albs = aws_client.elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])
        assert albs["LoadBalancers"][0]["LoadBalancerArn"] == alb_arn

    @markers.aws.unknown
    def test_scenario_call_service(self, aws_client, infrastructure):
        # TODO: add a test here to call the deployed NGINX service
        # outputs = infrastructure.get_stack_outputs(stack_name="ClusterStack")
        requests.get("...")  # not working yet
