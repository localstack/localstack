import aws_cdk as cdk
import aws_cdk.aws_ecs as ecs
import aws_cdk.aws_stepfunctions as sfn
import aws_cdk.aws_stepfunctions_tasks as tasks
import pytest

from localstack.testing.pytest import markers
from localstack.utils.analytics.metadata import is_license_activated
from tests.aws.services.stepfunctions.utils import await_execution_terminated


# TODO: figure out a better way, maybe via marker? e.g. @markers.localstack.ext
# @pytest.mark.skipif(condition=not is_license_activated())
class TestTaskServiceECS:
    STACK_NAME = "StepFunctionsEcsTaskStack"

    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client, infrastructure_setup):
        infra = infrastructure_setup(namespace="StepFunctionsEcsTask", force_synth=True)
        stack = cdk.Stack(infra.cdk_app, self.STACK_NAME)

        # cluster setup
        cluster = ecs.Cluster(stack, "cluster")

        # task setup
        launch_target = tasks.EcsFargateLaunchTarget(
            platform_version=ecs.FargatePlatformVersion.VERSION1_4
        )
        task_def = ecs.FargateTaskDefinition(stack, "taskdef", cpu=256, memory_limit_mib=512)
        task_def.add_container(
            "maincontainer",
            image=ecs.ContainerImage.from_registry("busybox"),
            entry_point=["echo", "hello"],
            essential=True,
        )

        # state machine setup
        run_task = tasks.EcsRunTask(
            stack,
            "ecstask",
            cluster=cluster,
            launch_target=launch_target,
            task_definition=task_def,
            integration_pattern=sfn.IntegrationPattern.RUN_JOB,
        )
        definition_body = sfn.DefinitionBody.from_chainable(run_task)
        statemachine = sfn.StateMachine(stack, "statemachine", definition_body=definition_body)

        # stack outputs
        cdk.CfnOutput(stack, "StateMachineArn", value=statemachine.state_machine_arn)
        cdk.CfnOutput(stack, "ClusterName", value=cluster.cluster_name)

        # provisioning
        with infra.provisioner(skip_deployment=False, skip_teardown=True) as prov:
            yield prov

    @markers.aws.validated
    def test_run_machine(self, aws_client, infrastructure, snapshot):
        # TODO: transformers potentially needed for all the ECS task outputs
        # TODO: generate snapshot
        outputs = infrastructure.get_stack_outputs(stack_name=self.STACK_NAME)
        sm_arn = outputs["StateMachineArn"]
        cluster_name = outputs["ClusterName"]

        cluster = aws_client.ecs.describe_clusters(clusters=[cluster_name])["clusters"][0]
        snapshot.match("cluster", cluster)
        execution_arn = aws_client.stepfunctions.start_execution(stateMachineArn=sm_arn)[
            "executionArn"
        ]
        await_execution_terminated(aws_client.stepfunctions, execution_arn)
        assert (
            aws_client.stepfunctions.describe_execution(executionArn=execution_arn)["status"]
            == "SUCCEEDED"
        )
        execution = aws_client.stepfunctions.describe_execution(executionArn=execution_arn)
        snapshot.match("execution", execution)

        execution_history = (
            aws_client.stepfunctions.get_paginator("get_execution_history")
            .paginate(executionArn=execution_arn)
            .build_full_result()
        )
        snapshot.match("execution_history", execution_history)
