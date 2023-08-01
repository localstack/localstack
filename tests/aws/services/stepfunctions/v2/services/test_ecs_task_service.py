import aws_cdk as cdk
import aws_cdk.aws_ecs as ecs
import aws_cdk.aws_stepfunctions as sfn
import aws_cdk.aws_stepfunctions_tasks as tasks
import pytest

from localstack.testing.pytest import markers
from localstack.testing.scenario.provisioning import InfraProvisioner
from tests.integration.stepfunctions.utils import await_execution_terminated


@pytest.mark.skip(reason="WIP")
class TestTaskServiceECS:
    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client):
        app = cdk.App()
        stack = cdk.Stack(app, "ClusterStack")

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
        statemachine = sfn.StateMachine(stack, "statemachine", definition=run_task)

        # stack outputs
        cdk.CfnOutput(stack, "StateMachineArn", value=statemachine.state_machine_arn)
        cdk.CfnOutput(stack, "ClusterName", value=cluster.cluster_name)

        # provisioning
        provisioner = InfraProvisioner(aws_client)
        provisioner.add_cdk_stack(stack)
        with provisioner.provisioner() as prov:
            yield prov

    # TODO: snapshot
    @markers.parity.aws_validated
    def test_run_machine(self, aws_client, infrastructure):
        sm_arn = infrastructure.get_stack_outputs(stack_name="ClusterStack")["StateMachineArn"]
        execution_arn = aws_client.stepfunctions.start_execution(stateMachineArn=sm_arn)[
            "executionArn"
        ]
        await_execution_terminated(aws_client.stepfunctions, execution_arn)
        assert (
            aws_client.stepfunctions.describe_execution(executionArn=execution_arn)["status"]
            == "SUCCEEDED"
        )
