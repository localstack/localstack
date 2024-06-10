import itertools
import json

import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.stepfunctions import (
    CloudWatchLogsLogGroup,
    LogDestination,
    LoggingConfiguration,
    LogLevel,
)
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import create
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate

_TEST_LOGGING_CONFIGURATIONS = list(
    itertools.product(
        # log level:
        [LogLevel.ALL, LogLevel.FATAL, LogLevel.ERROR, LogLevel.OFF],
        # include execution data
        [False, True],
    )
)
_TEST_INVALID_LOGGING_CONFIGURATIONS = [
    LoggingConfiguration(level=LogLevel.ALL),
    LoggingConfiguration(level=LogLevel.FATAL),
    LoggingConfiguration(level=LogLevel.ERROR),
]
_TEST_INCOMPLETE_LOGGING_CONFIGURATIONS = [
    LoggingConfiguration(),
    LoggingConfiguration(destinations=list()),
]


@markers.snapshot.skip_snapshot_verify(paths=["$..tracingConfiguration"])
class TestSnfApiLogs:
    @markers.aws.validated
    @pytest.mark.parametrize("logging_level,include_execution_data", _TEST_LOGGING_CONFIGURATIONS)
    def test_logging_configuration(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_create_log_group,
        sfn_snapshot,
        aws_client,
        logging_level,
        include_execution_data,
    ):
        log_group_name = sfn_create_log_group()
        log_group_arn = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)[
            "logGroups"
        ][0]["arn"]
        logging_configuration = LoggingConfiguration(
            level=logging_level,
            includeExecutionData=include_execution_data,
            destinations=[
                LogDestination(
                    cloudWatchLogsLogGroup=CloudWatchLogsLogGroup(logGroupArn=log_group_arn)
                ),
            ],
        )

        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp = create_state_machine(
            name=sm_name,
            definition=definition_str,
            roleArn=snf_role_arn,
            loggingConfiguration=logging_configuration,
        )
        state_machine_arn = creation_resp["stateMachineArn"]
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        sfn_snapshot.match("creation_resp", creation_resp)

        describe_resp = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp", describe_resp)

    @markers.aws.validated
    @pytest.mark.parametrize("logging_configuration", _TEST_INCOMPLETE_LOGGING_CONFIGURATIONS)
    def test_incomplete_logging_configuration(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_create_log_group,
        sfn_snapshot,
        aws_client,
        logging_configuration,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp = create_state_machine(
            name=sm_name,
            definition=definition_str,
            roleArn=snf_role_arn,
            loggingConfiguration=logging_configuration,
        )
        state_machine_arn = creation_resp["stateMachineArn"]
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        sfn_snapshot.match("creation_resp", creation_resp)

        describe_resp = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp", describe_resp)

    @markers.aws.validated
    @pytest.mark.parametrize("logging_configuration", _TEST_INVALID_LOGGING_CONFIGURATIONS)
    def test_invalid_logging_configuration(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_create_log_group,
        sfn_snapshot,
        aws_client,
        aws_client_factory,
        logging_configuration,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        template = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition = json.dumps(template)

        sm_name = f"statemachine_{short_uid()}"

        stepfunctions_client = aws_client_factory(
            config=Config(parameter_validation=False)
        ).stepfunctions
        with pytest.raises(ClientError) as exc:
            stepfunctions_client.create_state_machine(
                name=sm_name,
                definition=definition,
                roleArn=snf_role_arn,
                loggingConfiguration=logging_configuration,
            )
        sfn_snapshot.match(
            "exception", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

    @markers.aws.validated
    def test_deleted_log_group(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_create_log_group,
        sfn_snapshot,
        aws_client,
    ):
        logs_client = aws_client.logs
        log_group_name = sfn_create_log_group()
        log_group_arn = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)[
            "logGroups"
        ][0]["arn"]
        logging_configuration = LoggingConfiguration(
            level=LogLevel.ALL,
            destinations=[
                LogDestination(
                    cloudWatchLogsLogGroup=CloudWatchLogsLogGroup(logGroupArn=log_group_arn)
                ),
            ],
        )
        logs_client.delete_log_group(logGroupName=log_group_name)

        def _log_group_is_deleted() -> bool:
            return not logs_client.describe_log_groups(logGroupNamePrefix=log_group_name).get(
                "logGroups", None
            )

        assert poll_condition(condition=_log_group_is_deleted)

        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        template = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition = json.dumps(template)

        with pytest.raises(ClientError) as exc:
            create(
                create_iam_role_for_sfn,
                create_state_machine,
                sfn_snapshot,
                definition,
                logging_configuration,
            )
        sfn_snapshot.match(
            "exception", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

    @markers.aws.validated
    def test_multiple_destinations(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_create_log_group,
        sfn_snapshot,
        aws_client,
    ):
        logging_configuration = LoggingConfiguration(level=LogLevel.ALL, destinations=[])
        for i in range(2):
            log_group_name = sfn_create_log_group()
            log_group_arn = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)[
                "logGroups"
            ][0]["arn"]
            logging_configuration["destinations"].append(
                LogDestination(
                    cloudWatchLogsLogGroup=CloudWatchLogsLogGroup(logGroupArn=log_group_arn)
                )
            )

        template = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition = json.dumps(template)

        with pytest.raises(ClientError) as exc:
            create(
                create_iam_role_for_sfn,
                create_state_machine,
                sfn_snapshot,
                definition,
                logging_configuration,
            )
        sfn_snapshot.match(
            "exception", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

    @markers.aws.validated
    def test_update_logging_configuration(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_create_log_group,
        sfn_snapshot,
        aws_client,
        aws_client_factory,
    ):
        stepfunctions_client = aws_client_factory(
            config=Config(parameter_validation=False)
        ).stepfunctions

        log_group_name = sfn_create_log_group()
        log_group_arn = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)[
            "logGroups"
        ][0]["arn"]
        base_logging_configuration = LoggingConfiguration(
            level=LogLevel.ALL,
            includeExecutionData=True,
            destinations=[
                LogDestination(
                    cloudWatchLogsLogGroup=CloudWatchLogsLogGroup(logGroupArn=log_group_arn)
                ),
            ],
        )

        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp = create_state_machine(
            name=sm_name,
            definition=definition_str,
            roleArn=snf_role_arn,
            loggingConfiguration=base_logging_configuration,
        )
        state_machine_arn = creation_resp["stateMachineArn"]
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        sfn_snapshot.match("creation_resp", creation_resp)

        describe_resp = stepfunctions_client.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp", describe_resp)

        # Update LogLevel Value.
        base_logging_configuration["level"] = LogLevel.FATAL
        stepfunctions_client.update_state_machine(
            stateMachineArn=state_machine_arn, loggingConfiguration=base_logging_configuration
        )
        describe_resp_log_level = stepfunctions_client.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_log_level", describe_resp_log_level)

        # Empty update
        stepfunctions_client.update_state_machine(
            stateMachineArn=state_machine_arn, loggingConfiguration=base_logging_configuration
        )
        describe_resp_no_change = stepfunctions_client.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_no_change", describe_resp_no_change)

        # Update inclusion flag.
        base_logging_configuration["includeExecutionData"] = False
        stepfunctions_client.update_state_machine(
            stateMachineArn=state_machine_arn, loggingConfiguration=base_logging_configuration
        )
        describe_resp_flag = stepfunctions_client.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_flag", describe_resp_flag)

        # Add logging endpoints.
        log_group_name_2 = sfn_create_log_group()
        log_group_arn_2 = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name_2)[
            "logGroups"
        ][0]["arn"]
        base_logging_configuration["destinations"].append(
            LogDestination(
                cloudWatchLogsLogGroup=CloudWatchLogsLogGroup(logGroupArn=log_group_arn_2)
            )
        )
        with pytest.raises(ClientError) as exc:
            stepfunctions_client.update_state_machine(
                stateMachineArn=state_machine_arn, loggingConfiguration=base_logging_configuration
            )
        sfn_snapshot.match(
            "exception_multiple_endpoints",
            {"exception_typename": exc.typename, "exception_value": exc.value},
        )

        # Set invalid configuration.
        with pytest.raises(ClientError) as exc:
            stepfunctions_client.update_state_machine(
                stateMachineArn=state_machine_arn,
                loggingConfiguration=LoggingConfiguration(level=LogLevel.ALL),
            )
        sfn_snapshot.match(
            "exception_invalid", {"exception_typename": exc.typename, "exception_value": exc.value}
        )
