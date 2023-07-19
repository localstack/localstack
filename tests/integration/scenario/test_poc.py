"""
Notes

We assume order of test declaration => test execution (pytest default)
Need to be mindful of state drift
execution of tests should never be split inside classes (shouldn't be the case anyway right now)



Ideas:

* custom state reset / state validators between tests?


Todos:

* warn if a CDK construct is used that would create an asset
* make the InfraProvisioner into a fixture and add a pytest hook implementation

"""
import json

import aws_cdk as cdk
import pytest
import requests

from localstack.aws.connect import ServiceLevelClientFactory


class BotoDeployment:
    def setup(self):
        ...

    def teardown(self):
        ...


class TestSomeScenario:
    @pytest.fixture(scope="class", autouse=True)
    def define_infrastructure(self, aws_client):
        # CDK setup
        app = cdk.App()
        stack = cdk.Stack(app, "ClusterStack")

        # TODO: cdk.context.json equivalent
        # vpc = cdk.aws_ec2.Vpc.from_lookup(is_default=True)
        # cluster = cdk.aws_ecs.Cluster(stack1, "SomeCluster", vpc=vpc)

        cluster = cdk.aws_ecs.Cluster(stack, "SomeCluster")
        # TODO: task def
        # TODO: service

        cdk.aws_ecs_patterns.ApplicationLoadBalancedFargateService(
            stack2,
            "Wow",
            task_image_options=cdk.aws_ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                image=cdk.aws_ecs.ContainerImage.from_registry("amazon/amazon-ecs-sample")
            ),
        )

        # cdk.aws_s3_deployment.BucketDeployment(this, 'bucketdeploy')
        topic1 = cdk.aws_sns.Topic(stack1, "Topic")
        topic2 = cdk.aws_sns.Topic(stack2, "Topic")
        provisioner = InfraProvisioner(aws_client)
        # will be cleaned up in reverse order
        # provisioner.add_boto_step(setup_func, teardown_func)
        provisioner.add_cdk_stack(stack1)
        # provisioner.add_cdk_app(app, "my-first-scenario-1")
        # provisioner.add_custom_step(teardown=clean_s3_bucket)

        cdk.aws_iam.CfnUser(stack, "User", user_name="CustomName")

        provisioner.provision()
        yield provisioner
        provisioner.teardown()

    # ... state initialization
    # def initialize_state(self, aws_client):
    #     """
    #     Initialize application state
    #     """
    #     ...
    #     table_name = "...."
    #     aws_client.dynamodb.put_items(TableName=table_name, ....)

    ### TESTS

    # def test_infra_state(self, define_infrastructure):
    #     provisioner = define_infrastructure
    #     print(":/")
    #
    #     # we need:
    #     # access to deployed stacks & resources, responses from create calls
    #

    def test_scenario1(self, aws_client):
        sqs_client = aws_client.sqs
        sqs_client.send_message(QueueUrl="...", MessageBody="...")

        logs = aws_client.logs.filter_log_events(...)
        assert logs  # something

    def test_scenario_run_task(self, aws_client):
        # aws_client.ecs.run_task(taskDefinition=)

        requests.get("...")
