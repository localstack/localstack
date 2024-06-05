import itertools
import json

import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer
from rolo.testing.pytest import poll_condition

from localstack.aws.api.stepfunctions import (
    CloudWatchLogsLogGroup,
    LogDestination,
    LoggingConfiguration,
    LogLevel,
)
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create,
    create_and_record_execution_logs,
    launch_and_record_execution,
    launch_and_record_logs,
)
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate

_TEST_BASE_CONFIGURATIONS = list(
    itertools.product(
        # test case:
        [
            BaseTemplate.BASE_PASS_RESULT,
            BaseTemplate.BASE_RAISE_FAILURE,
            BaseTemplate.WAIT_SECONDS_PATH,
        ],
        # log level:
        [LogLevel.ALL],
        # include execution data
        [False, True],
    )
)
_TEST_BASE_CONFIGURATIONS_IDS = [
    f"{config[0].split('/')[-1]}_{config[1]}_{config[2]}" for config in _TEST_BASE_CONFIGURATIONS
]

_TEST_PARTIAL_LOG_LEVEL_CONFIGURATIONS = list(
    itertools.product(
        # test case:
        [
            BaseTemplate.BASE_PASS_RESULT,
            # BaseTemplate.BASE_RAISE_FAILURE,
            # BaseTemplate.WAIT_SECONDS_PATH,
        ],
        # log level:
        [LogLevel.ERROR],
        # [LogLevel.ERROR, LogLevel.FATAL, LogLevel.OFF],
        # include execution data
        # [False, True],
        [True],
    )
)
_TEST_PARTIAL_LOG_LEVEL_CONFIGURATIONS_IDS = [
    f"{config[0].split('/')[-1]}_{config[1]}_{config[2]}"
    for config in _TEST_PARTIAL_LOG_LEVEL_CONFIGURATIONS
]


@markers.snapshot.skip_snapshot_verify(
    paths=["$..tracingConfiguration", "$..redriveCount", "$..redrive_count", "$..redriveStatus"]
)
class TestLogs:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "template_path,log_level,include_flag",
        _TEST_BASE_CONFIGURATIONS,
        ids=_TEST_BASE_CONFIGURATIONS_IDS,
    )
    @markers.snapshot.skip_snapshot_verify(paths=["$..cause"])
    def test_base(
        self,
        aws_client,
        create_iam_role_for_sfn,
        sfn_create_log_group,
        create_state_machine,
        sfn_snapshot,
        template_path,
        log_level,
        include_flag,
    ):
        template = BaseTemplate.load_sfn_template(template_path)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution_logs(
            aws_client,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_create_log_group,
            sfn_snapshot,
            definition,
            exec_input,
            log_level,
            include_flag,
        )

    @markers.aws.validated
    @pytest.mark.parametrize(
        "template_path,log_level,include_flag",
        _TEST_PARTIAL_LOG_LEVEL_CONFIGURATIONS,
        ids=_TEST_PARTIAL_LOG_LEVEL_CONFIGURATIONS_IDS,
    )
    def test_partial_log_levels(
        self,
        aws_client,
        create_iam_role_for_sfn,
        sfn_create_log_group,
        create_state_machine,
        sfn_snapshot,
        template_path,
        log_level,
        include_flag,
    ):
        log_group_name = sfn_create_log_group()
        log_group_arn = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)[
            "logGroups"
        ][0]["arn"]
        logging_configuration = LoggingConfiguration(
            level=log_level,
            includeExecutionData=include_flag,
            destinations=[
                LogDestination(
                    cloudWatchLogsLogGroup=CloudWatchLogsLogGroup(logGroupArn=log_group_arn)
                ),
            ],
        )

        template = BaseTemplate.load_sfn_template(template_path)
        definition = json.dumps(template)

        state_machine_arn = create(
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            logging_configuration,
        )

        execution_input = json.dumps({})
        launch_and_record_execution(
            aws_client.stepfunctions,
            sfn_snapshot,
            state_machine_arn,
            execution_input,
        )

        logs_client = aws_client.logs
        log_streams = logs_client.describe_log_streams(logGroupName=log_group_name)["logStreams"]
        if len(log_streams) < 2:
            # No logs recorded resulted in no log stream creation.
            return

        log_stream_name = log_streams[-1]["logStreamName"]

        log_events = logs_client.get_log_events(
            logGroupName=log_group_name, logStreamName=log_stream_name, startFromHead=True
        )["events"]

        events = [json.loads(e["message"]) for e in log_events]
        logged_execution_events = sorted(events, key=lambda event: int(event.get("id")))

        sfn_snapshot.match("logged_execution_events", logged_execution_events)

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

        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        template = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition = json.dumps(template)

        state_machine_arn = create(
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            logging_configuration,
        )

        logs_client.delete_log_group(logGroupName=log_group_name)

        def _log_group_is_deleted() -> bool:
            return not logs_client.describe_log_groups(logGroupNamePrefix=log_group_name).get(
                "logGroups", None
            )

        poll_condition(condition=_log_group_is_deleted)

        execution_input = json.dumps({})
        launch_and_record_execution(
            aws_client.stepfunctions,
            sfn_snapshot,
            state_machine_arn,
            execution_input,
        )

    @markers.aws.validated
    def test_log_group_with_multiple_runs(
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

        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        template = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition = json.dumps(template)

        state_machine_arn = create(
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            logging_configuration,
        )

        execution_input = json.dumps({})
        launch_and_record_logs(
            aws_client,
            sfn_snapshot,
            state_machine_arn,
            log_group_name,
            execution_input,
        )

        launch_and_record_logs(
            aws_client,
            sfn_snapshot,
            state_machine_arn,
            log_group_name,
            execution_input,
        )
