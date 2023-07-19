import aws_cdk as cdk
import aws_cdk.aws_ecs as ecs
import pytest
import requests

from localstack.testing.scenario.provisioning import InfraProvisioner


class TestEcsScenario:
    @pytest.fixture(scope="class", autouse=True)
    def define_infrastructure(self, aws_client):
        app = cdk.App()
        stack = cdk.Stack(app, "ClusterStack")
        cluster = ecs.Cluster(stack, "MyCluster")
        cdk.aws_ecs_patterns.ApplicationLoadBalancedFargateService(
            stack,
            "balancedService",
            task_image_options=cdk.aws_ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                image=ecs.ContainerImage.from_registry("nginx"),
                container_port=80,
            ),
            desired_count=1,
            listener_port=8080,
        )

        provisioner = InfraProvisioner(aws_client)
        provisioner.add_cdk_stack(stack)
        provisioner.provision()
        yield provisioner
        provisioner.teardown()

    def test_scenario_run_task(self, aws_client):
        ecs_client = aws_client.ecs
        clusters = ecs_client.list_clusters()

        print("done")
