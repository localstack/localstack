import logging

import aws_cdk as cdk
import pytest

from localstack.testing.pytest import markers

LOG = logging.getLogger(__name__)


class TestWordpressBlogScenario:
    STACK_NAME = "WordpressStack"
    DB_USER = "wordpress"
    DB_PASSWORD = "wordpress-password"
    DB_NAME = "wordpress"

    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client, infrastructure_setup):
        infra = infrastructure_setup(namespace="NoteTaking")
        stack = cdk.Stack(infra.cdk_app, self.STACK_NAME)
        vpc = cdk.aws_ec2.Vpc(
            stack,
            "VPC",
            nat_gateways=1,
            cidr="10.0.0.0/16",
            subnet_configuration=[
                cdk.aws_ec2.SubnetConfiguration(
                    name="public", subnet_type=cdk.aws_ec2.SubnetType.PUBLIC, cidr_mask=24
                ),
                cdk.aws_ec2.SubnetConfiguration(
                    name="private",
                    subnet_type=cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24,
                ),
            ],
        )
        cdk.aws_ec2.SecurityGroup(
            stack,
            "cluster-sec-group",
            security_group_name="cluster-sec-group",
            vpc=vpc,
            allow_all_outbound=True,
        )

        database = cdk.aws_rds.DatabaseInstance(
            stack,
            "WordpressDatabase",
            credentials=cdk.aws_rds.Credentials.from_password(
                username=self.DB_USER, password=cdk.SecretValue.unsafe_plain_text(self.DB_PASSWORD)
            ),
            database_name=self.DB_NAME,
            engine=cdk.aws_rds.DatabaseInstanceEngine.MARIADB,
            vpc=vpc,
        )

        # ECS cluster
        cluster = cdk.aws_ecs.Cluster(stack, "ServiceCluster", vpc=vpc)

        wp_health_check = cdk.aws_ecs.HealthCheck(
            command=[
                "CMD-SHELL",
                'curl -s -o /dev/null -w "%{http_code}" http://localhost | grep -qE "200|301|302"',
            ],
            start_period=cdk.Duration.minutes(2),
        )

        docker_image = cdk.aws_ecs.ContainerImage.from_registry("wordpress")
        web_service = cdk.aws_ecs_patterns.ApplicationLoadBalancedFargateService(
            stack,
            "Wordpress",
            cluster=cluster,
            target_protocol=cdk.aws_elasticloadbalancingv2.ApplicationProtocol.HTTP,
            protocol=cdk.aws_elasticloadbalancingv2.ApplicationProtocol.HTTP,
            health_check=wp_health_check,
            desired_count=1,
            cpu=512,
            memory_limit_mib=2048,
            task_image_options=cdk.aws_ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                image=docker_image,
                container_port=80,
                container_name="webapp",
                enable_logging=True,
                environment={
                    "WORDPRESS_DB_HOST": f"{database.db_instance_endpoint_address}:{database.db_instance_endpoint_port}",
                    "WORDPRESS_DB_USER": self.DB_USER,
                    "WORDPRESS_DB_PASSWORD": self.DB_PASSWORD,
                    "WORDPRESS_DB_NAME": self.DB_NAME,
                },
            ),
        )

        web_service.target_group.configure_health_check(
            path="/index.php",
            healthy_http_codes="200,301,302",
            interval=cdk.Duration.seconds(120),
            unhealthy_threshold_count=10,
        )

        database.connections.allow_default_port_from(web_service.service.connections)

        cdk.CfnOutput(stack, "WordpressURL", value=web_service.load_balancer.load_balancer_dns_name)
        with infra.provisioner() as prov:
            yield prov

    @markers.aws.validated
    def test_deployment(self, infrastructure, aws_client, snapshot):
        resources = aws_client.cloudformation.list_stack_resources(StackName=self.STACK_NAME)
        snapshot.match("list_stack_resources", resources)
