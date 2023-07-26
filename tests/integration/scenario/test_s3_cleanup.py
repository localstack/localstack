import aws_cdk as cdk
import aws_cdk.aws_s3 as s3
import pytest

from localstack.testing.scenario.provisioning import InfraProvisioner
from localstack.utils.strings import to_str


class TestEcsScenario:
    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client):
        app = cdk.App()
        stack = cdk.Stack(app, "BucketCleanupStack")
        bucket1 = s3.Bucket(stack, "Bucket1")
        bucket2 = s3.Bucket(stack, "Bucket2")

        cdk.CfnOutput(stack, "Bucket1Name", value=bucket1.bucket_name)
        cdk.CfnOutput(stack, "Bucket2Name", value=bucket2.bucket_name)

        provisioner = InfraProvisioner(aws_client)
        provisioner.add_cdk_stack(stack)
        provisioner.provision()
        yield provisioner
        provisioner.teardown()

    def test_scenario_validate_infra(self, aws_client, infrastructure):
        outputs = infrastructure.get_stack_outputs(stack_name="BucketCleanupStack")
        bucket1_name = outputs["Bucket1Name"]  # noqa
        bucket2_name = outputs["Bucket2Name"]

        aws_client.s3.put_object(Bucket=bucket2_name, Key="bla", Body="Hello World!")

        returned_obj = aws_client.s3.get_object(Bucket=bucket2_name, Key="bla")
        assert "bla" in to_str(returned_obj["Body"].read())
