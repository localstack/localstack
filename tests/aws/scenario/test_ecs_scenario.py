import time

import aws_cdk as cdk
import aws_cdk.aws_ecs as ecs
import pytest
import requests

from localstack.testing.pytest import markers
from localstack.testing.scenario.provisioning import InfraProvisioner


@pytest.mark.skip(
    reason="requires pro",
)
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



class TestEcsScenario2:
    @markers.aws.unknown
    def test_scenario_ecs(self, aws_client):
        vpc = aws_client.ec2.create_vpc(CidrBlock="0.0.0.0/16")
        vpc_id = vpc['Vpc']['VpcId']
        subnet = aws_client.ec2.create_subnet(VpcId=vpc_id, CidrBlock="0.0.0.0/24")
        cluster = aws_client.ecs.create_cluster(clusterName="dev-cluster")
        task_def = aws_client.ecs.register_task_definition(
            family="sample-fargate",
            taskRoleArn="arn:aws:iam::000000000000:role/execCommandRole",
            networkMode="awsvpc",
            containerDefinitions=[
                {
                    "name": "fargate-app",
                    "image": "public.ecr.aws/docker/library/httpd:latest",
                    "command": [
                        "/bin/sh",
                        "-c",
                        "echo '<html> <head> <title>Amazon ECS Sample App</title> <style>body {margin-top: 40px; background-color: #333;} </style> </head><body> <div style=color:white;text-align:center> <h1>Amazon ECS Sample App</h1> <h2>Congratulations!</h2> <p>Your application is now running on a container in Amazon ECS.</p> </div></body></html>' >  /usr/local/apache2/htdocs/index.html && httpd-foreground"
                    ],
                    "portMappings": [
                        {
                            "containerPort": 80,
                            "hostPort": 45139,
                            "protocol": "tcp"
                        }
                    ],
                    "essential": True,
                }
            ],
            requiresCompatibilities=["FARGATE"],
            cpu="256",
            memory="512",

        )

        service = aws_client.ecs.create_service(
            cluster="dev-cluster",
            serviceName="fargate-service",
            desiredCount=1,
            taskDefinition="sample-fargate",
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": [
                        subnet['Subnet']['SubnetId']
                    ]
                }
            },
        )
