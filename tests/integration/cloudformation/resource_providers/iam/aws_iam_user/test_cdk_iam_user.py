import aws_cdk as cdk
import aws_cdk.aws_iam as iam
import pytest

from localstack.testing.scenario.provisioning import InfraProvisioner


class ParityMarker:
    aws_validated = pytest.mark.aws_validated
    should_be_aws_validated = pytest.mark.should_be_aws_validated
    localstack_only = pytest.mark.localstack_only
    aws_validated_with_manual_setup = pytest.mark.aws_validated_with_manual_setup


class TestBasicIamUser:
    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client):
        # stack definition
        stack = cdk.Stack(cdk.App(), "AwsIamUserStack")
        user = iam.CfnUser(stack, "user")
        cdk.CfnOutput(stack, "UserRef", value=user.ref)

        # provisioning
        provisioner = InfraProvisioner(aws_client)
        provisioner.add_cdk_stack(stack)
        provisioner.provision()
        yield provisioner
        provisioner.teardown()

    def test_scenario_validate_infra(self, aws_client, infrastructure):
        outputs = infrastructure.get_stack_outputs(stack_name="AwsIamUserStack")
        user_name = outputs["UserRef"]
        aws_client.iam.get_user(UserName=user_name)

    # TODO: more tests/validations
