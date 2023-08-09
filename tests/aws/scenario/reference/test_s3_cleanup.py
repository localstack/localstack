import aws_cdk as cdk
import aws_cdk.aws_s3 as s3
import pytest

from localstack.testing.pytest import markers
from localstack.testing.scenario.provisioning import InfraProvisioner
from localstack.utils.strings import to_str


class TestS3CleanupScenario:
    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client):
        app = cdk.App()
        stack = cdk.Stack(app, "BucketCleanupStack")
        bucket1 = s3.Bucket(stack, "Bucket1", removal_policy=cdk.RemovalPolicy.DESTROY)
        bucket2 = s3.Bucket(stack, "Bucket2", removal_policy=cdk.RemovalPolicy.DESTROY)

        cdk.CfnOutput(stack, "Bucket1Name", value=bucket1.bucket_name)
        cdk.CfnOutput(stack, "Bucket2Name", value=bucket2.bucket_name)

        provisioner = InfraProvisioner(aws_client)
        provisioner.add_cdk_stack(stack, autoclean_buckets=True)

        try:
            provisioner.provision()
            yield provisioner
        finally:
            provisioner.teardown()

    @markers.aws.unknown
    def test_scenario_validate_infra(self, aws_client, infrastructure):
        outputs = infrastructure.get_stack_outputs(stack_name="BucketCleanupStack")
        bucket1_name = outputs["Bucket1Name"]  # noqa
        bucket2_name = outputs["Bucket2Name"]

        aws_client.s3.put_object(Bucket=bucket2_name, Key="bla", Body="Hello World!")

        # make sure we actually have something in the bucket now
        returned_obj = aws_client.s3.get_object(Bucket=bucket2_name, Key="bla")
        assert "Hello" in to_str(returned_obj["Body"].read())

        infrastructure.teardown()

        # make sure both buckets are gone now
        with pytest.raises(aws_client.s3.exceptions.ClientError):
            aws_client.s3.list_objects_v2(Bucket=bucket2_name)

        with pytest.raises(aws_client.s3.exceptions.ClientError):
            aws_client.s3.list_objects_v2(Bucket=bucket1_name)
