import aws_cdk as cdk

# import aws_cdk.aws_ecs as ecs
# import aws_cdk.aws_stepfunctions as sfn
# import aws_cdk.aws_stepfunctions_tasks as tasks
import pytest

from localstack.testing.scenario.provisioning import InfraProvisioner


@pytest.mark.skip(reason="WIP")
class TestTaskServiceEKS:
    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client):
        app = cdk.App()
        stack = cdk.Stack(app, "ClusterStack")

        # TODO
        # statemachine = sfn.StateMachine(stack, "statemachine", definition=run_task)
        #
        # cdk.CfnOutput(stack, "StateMachineArn", value=statemachine.state_machine_arn)
        # cdk.CfnOutput(stack, "ClusterName", value=cluster.cluster_name)

        provisioner = InfraProvisioner(aws_client)
        provisioner.add_cdk_stack(stack)
        with provisioner.provisioner(skip_teardown=True) as prov:
            yield prov

    def test_run(self, aws_client, infrastructure):
        ...
        # outputs = infrastructure.get_stack_outputs(stack_name="ClusterStack")
        # cluster_name = outputs["ClusterName"]
        # sm_arn = outputs["StateMachineArn"]
        # describe_machine = aws_client.stepfunctions.describe_state_machine(stateMachineArn=sm_arn)
