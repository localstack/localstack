import json

import aws_cdk as cdk
import aws_cdk.aws_ecs as ecs
import aws_cdk.aws_stepfunctions as sfn
import aws_cdk.aws_stepfunctions_tasks as tasks
import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import launch_and_record_execution
from localstack.utils.analytics.metadata import is_license_activated

_ECS_SNAPSHOT_SKIP_PATHS: [list[str]] = [
    "$..Attachments..Details",
    "$..Attachments..Id",
    "$..Attachments..Status",
    "$..Attachments..Type",
    "$..AvailabilityZone",
    "$..ClusterArn",
    "$..Connectivity",
    "$..ConnectivityAt",
    "$..Cpu",
    "$..DesiredStatus",
    "$..ExecutionStoppedAt",
    "$..GpuIds",
    "$..Group",
    "$..HealthStatus",
    "$..ImageDigest",
    "$..InferenceAccelerators",
    "$..LastStatus",
    "$..ManagedAgents",
    "$..Memory",
    "$..NetworkInterfaces",
    "$..Overrides.ContainerOverrides",
    "$..Overrides.InferenceAcceleratorOverrides",
    "$..PlatformFamily",
    "$..PullStartedAt",
    "$..PullStoppedAt",
    "$..RuntimeId",
    "$..SdkHttpMetadata",
    "$..SdkResponseMetadata",
    "$..StartedAt",
    "$..StopCode",
    "$..StoppedAt",
    "$..StoppedReason",
    "$..StoppingAt",
    "$..TaskDefinitionArn",
    "$..Version",
    "$..parameters.Cluster",
]


# TODO: figure out a better way, maybe via marker? e.g. @markers.localstack.ext
@pytest.mark.skipif(condition=not is_license_activated(), reason="integration test with pro")
class TestTaskServiceECS:
    STACK_NAME = "StepFunctionsEcsTaskStack"

    @pytest.fixture(scope="class", autouse=False)
    def infrastructure_test_run_task(self, aws_client, infrastructure_setup):
        infra = infrastructure_setup(namespace="StepFunctionsEcsTask", force_synth=False)
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
            launch_target=launch_target,  # noqa
            task_definition=task_def,
            integration_pattern=sfn.IntegrationPattern.REQUEST_RESPONSE,
        )
        definition_body = sfn.DefinitionBody.from_chainable(run_task)
        statemachine = sfn.StateMachine(stack, "statemachine", definition_body=definition_body)

        # stack outputs
        cdk.CfnOutput(stack, "TaskDefinitionArn", value=task_def.task_definition_arn)
        cdk.CfnOutput(stack, "ClusterArn", value=cluster.cluster_arn)
        cdk.CfnOutput(stack, "StateMachineArn", value=statemachine.state_machine_arn)
        cdk.CfnOutput(stack, "ClusterName", value=cluster.cluster_name)
        cdk.CfnOutput(stack, "StateMachineRoleArn", value=statemachine.role.role_arn)
        cdk.CfnOutput(stack, "TaskDefinitionFamily", value=task_def.family)
        cdk.CfnOutput(
            stack, "TaskDefinitionContainerName", value=task_def.default_container.container_name
        )

        # provisioning
        with infra.provisioner(skip_deployment=False, skip_teardown=False) as prov:
            yield prov

    @pytest.fixture(scope="class", autouse=False)
    def infrastructure_test_run_task_raise_failure(self, aws_client, infrastructure_setup):
        infra = infrastructure_setup(namespace="StepFunctionsEcsTask", force_synth=False)
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
            image=ecs.ContainerImage.from_registry("no_such_image"),
            entry_point=["echo", "hello"],
            essential=True,
        )

        # state machine setup
        run_task = tasks.EcsRunTask(
            stack,
            "ecstask",
            cluster=cluster,
            launch_target=launch_target,  # noqa
            task_definition=task_def,
            integration_pattern=sfn.IntegrationPattern.REQUEST_RESPONSE,
        )
        definition_body = sfn.DefinitionBody.from_chainable(run_task)
        statemachine = sfn.StateMachine(stack, "statemachine", definition_body=definition_body)

        # stack outputs
        cdk.CfnOutput(stack, "TaskDefinitionArn", value=task_def.task_definition_arn)
        cdk.CfnOutput(stack, "ClusterArn", value=cluster.cluster_arn)
        cdk.CfnOutput(stack, "StateMachineArn", value=statemachine.state_machine_arn)
        cdk.CfnOutput(stack, "ClusterName", value=cluster.cluster_name)
        cdk.CfnOutput(stack, "StateMachineRoleArn", value=statemachine.role.role_arn)
        cdk.CfnOutput(stack, "TaskDefinitionFamily", value=task_def.family)
        cdk.CfnOutput(
            stack, "TaskDefinitionContainerName", value=task_def.default_container.container_name
        )

        # provisioning
        with infra.provisioner(skip_deployment=False, skip_teardown=False) as prov:
            yield prov

    @pytest.fixture(scope="class", autouse=False)
    def infrastructure_test_run_task_sync(self, aws_client, infrastructure_setup):
        infra = infrastructure_setup(namespace="StepFunctionsEcsTask", force_synth=False)
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
            launch_target=launch_target,  # noqa
            task_definition=task_def,
            integration_pattern=sfn.IntegrationPattern.RUN_JOB,
        )
        definition_body = sfn.DefinitionBody.from_chainable(run_task)
        statemachine = sfn.StateMachine(stack, "statemachine", definition_body=definition_body)

        # stack outputs
        cdk.CfnOutput(stack, "TaskDefinitionArn", value=task_def.task_definition_arn)
        cdk.CfnOutput(stack, "ClusterArn", value=cluster.cluster_arn)
        cdk.CfnOutput(stack, "StateMachineArn", value=statemachine.state_machine_arn)
        cdk.CfnOutput(stack, "ClusterName", value=cluster.cluster_name)
        cdk.CfnOutput(stack, "StateMachineRoleArn", value=statemachine.role.role_arn)
        cdk.CfnOutput(stack, "TaskDefinitionFamily", value=task_def.family)
        cdk.CfnOutput(
            stack, "TaskDefinitionContainerName", value=task_def.default_container.container_name
        )

        # provisioning
        with infra.provisioner(skip_deployment=False, skip_teardown=False) as prov:
            yield prov

    @pytest.fixture(scope="class", autouse=False)
    def infrastructure_test_run_task_sync_raise_failure(self, aws_client, infrastructure_setup):
        infra = infrastructure_setup(namespace="StepFunctionsEcsTask", force_synth=False)
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
            image=ecs.ContainerImage.from_registry("no_such_image"),
            entry_point=["echo", "hello"],
            essential=True,
        )

        # state machine setup
        run_task = tasks.EcsRunTask(
            stack,
            "ecstask",
            cluster=cluster,
            launch_target=launch_target,  # noqa
            task_definition=task_def,
            integration_pattern=sfn.IntegrationPattern.RUN_JOB,
        )
        definition_body = sfn.DefinitionBody.from_chainable(run_task)
        statemachine = sfn.StateMachine(stack, "statemachine", definition_body=definition_body)

        # stack outputs
        cdk.CfnOutput(stack, "TaskDefinitionArn", value=task_def.task_definition_arn)
        cdk.CfnOutput(stack, "ClusterArn", value=cluster.cluster_arn)
        cdk.CfnOutput(stack, "StateMachineArn", value=statemachine.state_machine_arn)
        cdk.CfnOutput(stack, "ClusterName", value=cluster.cluster_name)
        cdk.CfnOutput(stack, "StateMachineRoleArn", value=statemachine.role.role_arn)
        cdk.CfnOutput(stack, "TaskDefinitionFamily", value=task_def.family)
        cdk.CfnOutput(
            stack, "TaskDefinitionContainerName", value=task_def.default_container.container_name
        )

        # provisioning
        with infra.provisioner(skip_deployment=False, skip_teardown=False) as prov:
            yield prov

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=[*_ECS_SNAPSHOT_SKIP_PATHS, "$..StartedBy"])
    def test_run_task(self, aws_client, infrastructure_test_run_task, sfn_ecs_snapshot):
        stack_outputs = infrastructure_test_run_task.get_stack_outputs(stack_name=self.STACK_NAME)
        state_machine_arn = stack_outputs["StateMachineArn"]

        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["TaskDefinitionArn"], "task_definition_arn")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["StateMachineRoleArn"], "state_machine_role_arn")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["ClusterArn"], "cluster_arn")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(
                stack_outputs["TaskDefinitionContainerName"], "task_definition_container_name"
            )
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["TaskDefinitionFamily"], "task_definition_family")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["ClusterName"], "cluster_name")
        )
        sfn_ecs_snapshot.add_transformer(RegexTransformer(state_machine_arn, "state_machine_arn"))

        launch_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            sfn_snapshot=sfn_ecs_snapshot,
            state_machine_arn=state_machine_arn,
            execution_input=json.dumps({}),
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=_ECS_SNAPSHOT_SKIP_PATHS)
    @pytest.mark.skip(reason="ECS Provider doesn't raise failure on invalid image.")
    def test_run_task_raise_failure(
        self, aws_client, infrastructure_test_run_task_raise_failure, sfn_ecs_snapshot
    ):
        stack_outputs = infrastructure_test_run_task_raise_failure.get_stack_outputs(
            stack_name=self.STACK_NAME
        )
        state_machine_arn = stack_outputs["StateMachineArn"]

        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["TaskDefinitionArn"], "task_definition_arn")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["StateMachineRoleArn"], "state_machine_role_arn")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["ClusterArn"], "cluster_arn")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(
                stack_outputs["TaskDefinitionContainerName"], "task_definition_container_name"
            )
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["TaskDefinitionFamily"], "task_definition_family")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["ClusterName"], "cluster_name")
        )
        sfn_ecs_snapshot.add_transformer(RegexTransformer(state_machine_arn, "state_machine_arn"))

        launch_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            sfn_snapshot=sfn_ecs_snapshot,
            state_machine_arn=state_machine_arn,
            execution_input=json.dumps({}),
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=_ECS_SNAPSHOT_SKIP_PATHS)
    def test_run_task_sync(self, aws_client, infrastructure_test_run_task_sync, sfn_ecs_snapshot):
        stack_outputs = infrastructure_test_run_task_sync.get_stack_outputs(
            stack_name=self.STACK_NAME
        )
        state_machine_arn = stack_outputs["StateMachineArn"]

        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["TaskDefinitionArn"], "task_definition_arn")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["StateMachineRoleArn"], "state_machine_role_arn")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["ClusterArn"], "cluster_arn")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(
                stack_outputs["TaskDefinitionContainerName"], "task_definition_container_name"
            )
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["TaskDefinitionFamily"], "task_definition_family")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["ClusterName"], "cluster_name")
        )
        sfn_ecs_snapshot.add_transformer(RegexTransformer(state_machine_arn, "state_machine_arn"))

        launch_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            sfn_snapshot=sfn_ecs_snapshot,
            state_machine_arn=state_machine_arn,
            execution_input=json.dumps({}),
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=_ECS_SNAPSHOT_SKIP_PATHS)
    @pytest.mark.skip(reason="ECS Provider doesn't raise failure on invalid image.")
    def test_run_task_sync_raise_failure(
        self, aws_client, infrastructure_test_run_task_sync_raise_failure, sfn_ecs_snapshot
    ):
        stack_outputs = infrastructure_test_run_task_sync_raise_failure.get_stack_outputs(
            stack_name=self.STACK_NAME
        )
        state_machine_arn = stack_outputs["StateMachineArn"]

        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["TaskDefinitionArn"], "task_definition_arn")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["StateMachineRoleArn"], "state_machine_role_arn")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["ClusterArn"], "cluster_arn")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(
                stack_outputs["TaskDefinitionContainerName"], "task_definition_container_name"
            )
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["TaskDefinitionFamily"], "task_definition_family")
        )
        sfn_ecs_snapshot.add_transformer(
            RegexTransformer(stack_outputs["ClusterName"], "cluster_name")
        )
        sfn_ecs_snapshot.add_transformer(RegexTransformer(state_machine_arn, "state_machine_arn"))

        launch_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            sfn_snapshot=sfn_ecs_snapshot,
            state_machine_arn=state_machine_arn,
            execution_input=json.dumps({}),
        )
