import aws_cdk as cdk

import aws_cdk.aws_batch as batch
import aws_cdk.aws_batch_alpha as batch_alpha
import aws_cdk.aws_stepfunctions as sfn
import aws_cdk.aws_stepfunctions_tasks as tasks
from aws_cdk.aws_ecs import ContainerImage, LogDriver
import pytest

from localstack.testing.scenario.provisioning import InfraProvisioner
from tests.integration.stepfunctions.utils import await_execution_terminated


# @pytest.mark.skip(reason="WIP")
class TestTaskServiceBatch:
    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client):
        app = cdk.App()
        stack = cdk.Stack(app, "SfnBatchStack")

        cdk.

        log_group = cdk.aws_logs.LogGroup(stack, "loggroup")
        container_def = batch_alpha.EcsFargateContainerDefinition(
            stack,
            "fargatecontainerdef",
            image=ContainerImage.from_registry("busybox"),
            memory=cdk.Size.mebibytes(1024),
            cpu=0.5,
            command=["echo", "hello"],
            logging=LogDriver.aws_logs(stream_prefix="testsfnecs", log_group=log_group),
        )
        job_def = batch_alpha.EcsJobDefinition(stack, "jobdef", container=container_def)
        vpc = cdk.aws_ec2.Vpc(stack, "vpc")
        compute_environment = batch_alpha.FargateComputeEnvironment(stack, "computeEnv", vpc=vpc)
        job_queue = batch_alpha.JobQueue(
            stack,
            "jobqueue",
            compute_environments=[batch_alpha.OrderedComputeEnvironment(compute_environment=compute_environment, order=1)]
        )
        start_state = tasks.BatchSubmitJob(
            stack,
            "submitjob",
            job_definition_arn=job_def.job_definition_arn,
            job_name="somejob",
            job_queue_arn=job_queue.job_queue_arn,
        )

        statemachine = sfn.StateMachine(stack, "statemachine", definition=start_state)

        cdk.CfnOutput(stack, "StateMachineArn", value=statemachine.state_machine_arn)
        cdk.CfnOutput(stack, "LogGroupName", value=log_group.log_group_name)
        # cdk.CfnOutput(stack, "ClusterName", value=cluster.cluster_name)

        provisioner = InfraProvisioner(aws_client)
        provisioner.add_cdk_stack(stack)
        with provisioner.provisioner(skip_teardown=True) as prov:
            yield prov

    def test_run_machine(self, aws_client, infrastructure):
        outputs = infrastructure.get_stack_outputs(stack_name="SfnBatchStack")
        log_group_name = outputs["LogGroupName"]
        sm_arn = outputs["StateMachineArn"]
        execution_arn = aws_client.stepfunctions.start_execution(stateMachineArn=sm_arn)[
            "executionArn"
        ]
        await_execution_terminated(aws_client.stepfunctions, execution_arn)
        assert (
                aws_client.stepfunctions.describe_execution(executionArn=execution_arn)["status"]
                == "SUCCEEDED"
        )
