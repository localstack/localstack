import json

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

STATE_MACHINE_ERROR = {
    "Comment": "An example of the Amazon States Language using a choice state.",
    "StartAt": "DefaultState",
    "States": {
        "DefaultState": {"Type": "Fail", "Error": "DefaultStateError", "Cause": "No Matches!"}
    },
}


class TestStepFunctionsPartitions:
    # We only have access to the AWS partition, not CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-2", "aws"), ("cn-north-1", "aws-cn")])
    def test_state_machine_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        sfn = aws_client_factory(region_name=region).stepfunctions

        name = f"state-machine-{short_uid()}"
        state_machine_arn = sfn.create_state_machine(
            name=name,
            definition=json.dumps(STATE_MACHINE_ERROR),
            roleArn="sth",
        )["stateMachineArn"]
        assert (
            state_machine_arn == f"arn:{partition}:states:{region}:{account_id}:stateMachine:{name}"
        )

        assert (
            sfn.describe_state_machine(stateMachineArn=state_machine_arn)["stateMachineArn"]
            == state_machine_arn
        )
