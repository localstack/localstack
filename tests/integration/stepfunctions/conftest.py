import logging
from typing import Final

import pytest

from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)


@pytest.fixture
def create_iam_role_for_sfn(create_iam_role_with_policy):
    role_name = f"test-snf-role-{short_uid()}"
    policy_name = f"test-lambda-policy-{short_uid()}"
    snf_role = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    snf_permission = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "lambda:*",
                    "sqs:*",
                    "dynamodb:*",
                    "secretsmanager:*",
                    "logs:*",
                ],
                "Resource": ["*"],
            }
        ],
    }

    def _create():
        return create_iam_role_with_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            RoleDefinition=snf_role,
            PolicyDefinition=snf_permission,
        )

    return _create


@pytest.fixture
def create_state_machine(stepfunctions_client):
    _state_machine_arns: Final[list[str]] = list()

    def _create_state_machine(**kwargs):
        create_output = stepfunctions_client.create_state_machine(**kwargs)
        create_output_arn = create_output["stateMachineArn"]
        _state_machine_arns.append(create_output_arn)
        return create_output

    yield _create_state_machine

    for state_machine_arn in _state_machine_arns:
        try:
            stepfunctions_client.delete_state_machine(stateMachineArn=state_machine_arn)
        except Exception:
            LOG.debug(f"Unable to delete state machine '{state_machine_arn}' during cleanup.")
