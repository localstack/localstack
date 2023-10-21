import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import pytest

from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)


@pytest.fixture
def cfn_store_events_role_arn(request, create_iam_role_with_policy, aws_client):
    """
    Create a role for use with CloudFormation, so that we can track CloudTrail
    events. For use with with the CFn resource provider scaffolding.

    To set this functionality up in your account, see the
    `localstack/services/cloudformation/cloudtrail_stack` directory.

    Once a test is run against AWS, wait around 5 minutes and check the bucket
    pointed to by the SSM parameter `cloudtrail-bucket-name`. Inside will be a
    path matching the name of the test, then a start time, then `events.json`.
    This JSON file contains the events that CloudTrail captured during this
    test execution.
    """
    if os.getenv("TEST_TARGET") != "AWS_CLOUD":
        LOG.error("cfn_store_events_role fixture does nothing unless targeting AWS")
        yield None
        return

    # check that the user has run the bootstrap stack

    try:
        step_function_arn = aws_client.ssm.get_parameter(
            Name="cloudtrail-stepfunction-arn",
        )[
            "Parameter"
        ]["Value"]
    except aws_client.ssm.exceptions.ParameterNotFound:
        LOG.error(
            "could not fetch step function arn from parameter store - have you run the setup stack?"
        )
        yield None
        return

    offset_time = timedelta(minutes=5)
    test_name = request.node.name
    start_time = datetime.now(tz=timezone.utc) - offset_time

    role_name = f"role-{short_uid()}"
    policy_name = f"policy-{short_uid()}"
    role_definition = {
        "Statement": {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {"Service": "cloudformation.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    }

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["*"],
                "Resource": ["*"],
            },
        ],
    }
    role_arn = create_iam_role_with_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        RoleDefinition=role_definition,
        PolicyDefinition=policy_document,
    )

    LOG.warning("sleeping for role creation")
    time.sleep(20)

    yield role_arn

    end_time = datetime.now(tz=timezone.utc) + offset_time

    stepfunctions_payload = {
        "test_name": test_name,
        "role_arn": role_arn,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
    }

    aws_client.stepfunctions.start_execution(
        stateMachineArn=step_function_arn, input=json.dumps(stepfunctions_payload)
    )
