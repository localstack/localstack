from unittest.mock import ANY, Mock, call

import pytest

from localstack.services.cloudwatch import alarm_scheduler
from localstack.services.cloudwatch.alarm_scheduler import COMPARISON_OPS
from localstack.utils.patch import Patch, Patches


class TestAlarmScheduler:
    TEST_1_DATA = "'0 - X - X'"
    TEST_2_DATA = "'0 - - - -'"
    TEST_3_DATA = "'- - - - -'"
    TEST_4_DATA = "'0 X X - X'"
    TEST_5_DATA = "'- - X - -'"

    TEST_1_M_OF_N = "'0 - X - X'"
    TEST_2_M_OF_N = "'0 0 X 0 X'"
    TEST_3_M_OF_N = "'0 - X - - '"
    TEST_4_M_OF_N = "'- - - - 0'"
    TEST_5_M_OF_N = "'- - - X -'"

    def test_comparison_operation_mapping(self):
        a = 3
        b = 4

        assert not COMPARISON_OPS.get("GreaterThanOrEqualToThreshold")(a, b)
        assert COMPARISON_OPS.get("GreaterThanOrEqualToThreshold")(a, a)
        assert COMPARISON_OPS.get("GreaterThanOrEqualToThreshold")(b, a)

        assert not COMPARISON_OPS.get("GreaterThanThreshold")(a, b)
        assert not COMPARISON_OPS.get("GreaterThanThreshold")(a, a)
        assert COMPARISON_OPS.get("GreaterThanThreshold")(b, a)

        assert COMPARISON_OPS.get("LessThanThreshold")(a, b)
        assert not COMPARISON_OPS.get("LessThanThreshold")(a, a)
        assert not COMPARISON_OPS.get("LessThanThreshold")(b, a)

        assert COMPARISON_OPS.get("LessThanOrEqualToThreshold")(a, b)
        assert COMPARISON_OPS.get("LessThanOrEqualToThreshold")(a, a)
        assert not COMPARISON_OPS.get("LessThanOrEqualToThreshold")(b, a)

    @pytest.mark.parametrize(
        "initial_state,expected_state,expected_calls,treat_missing,metric_data",
        [
            # 0 - X - X
            ("ALARM", "OK", 1, "missing", TEST_1_DATA),
            ("ALARM", "OK", 1, "ignore", TEST_1_DATA),
            ("ALARM", "OK", 1, "breaching", TEST_1_DATA),
            ("ALARM", "OK", 1, "notBreaching", TEST_1_DATA),
            # 0 - - - -
            ("ALARM", "OK", 1, "missing", TEST_2_DATA),
            ("ALARM", "OK", 1, "ignore", TEST_2_DATA),
            ("ALARM", "OK", 1, "breaching", TEST_2_DATA),
            ("ALARM", "OK", 1, "notBreaching", TEST_2_DATA),
            # - - - - -
            ("OK", "INSUFFICIENT_DATA", 1, "missing", TEST_3_DATA),
            ("OK", "OK", 0, "ignore", TEST_3_DATA),
            ("OK", "ALARM", 1, "breaching", TEST_3_DATA),
            ("OK", "OK", 0, "notBreaching", TEST_3_DATA),
            # 0 X X - X
            ("OK", "ALARM", 1, "missing", TEST_4_DATA),
            ("OK", "ALARM", 1, "ignore", TEST_4_DATA),
            ("OK", "ALARM", 1, "breaching", TEST_4_DATA),
            ("OK", "ALARM", 1, "notBreaching", TEST_4_DATA),
            # - - X - -
            ("INSUFFICIENT_DATA", "ALARM", 1, "missing", TEST_5_DATA),
            ("INSUFFICIENT_DATA", "INSUFFICIENT_DATA", 0, "ignore", TEST_5_DATA),
            ("INSUFFICIENT_DATA", "ALARM", 1, "breaching", TEST_5_DATA),
            ("INSUFFICIENT_DATA", "OK", 1, "notBreaching", TEST_5_DATA),
        ],
    )
    def test_calculate_alarm_state_3_out_of_3(
        self, initial_state, expected_state, expected_calls, treat_missing, metric_data
    ):
        """
        Tests Table 1 depicted in the docs: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html#alarm-evaluation
        Datapoints to Alarm and Evaluation Periods are both 3.
        Cloudwatch uses 5 latest datapoints for evaluation:
        0 = ok
        X = breaking threshold
        - = no data available
        |Test   | Data points  | MISSING          | IGNORE      | BREACHING | NOT BREACHING | # missing datapoints |
        |-------|--------------|------------------|-------------|-----------|---------------| ---------------------|
        |TEST_1 | 0 - X - X    | OK               | OK          | OK        | OK            | 0                    |
        |TEST_2 | 0 - - - -    | OK               | OK          | OK        | OK            | 2                    |
        |TEST_3 | - - - - -    | INSUFFICIENT_DATA| Retain state| ALARM     | OK            | 3                    |
        |TEST_4 | 0 X X - X    | ALARM            | ALARM       | ALARM     | ALARM         | 0                    |
        |TEST_5 | - - X - -    | ALARM            | Retain state| ALARM     | OK            | 2 -> Premature alarm |
        """

        def mock_metric_alarm_details(alarm_arn):
            details = {
                "AlarmName": "test-alarm",
                "StateValue": initial_state,
                "TreatMissingData": treat_missing,
                "DatapointsToAlarm": 3,
                "EvaluationPeriods": 3,
                "Period": 5,
                "ComparisonOperator": "LessThanThreshold",
                "Threshold": 2,
            }
            return details

        def mock_collect_metric_data(alarm_details, client):
            if metric_data == self.TEST_1_DATA:
                return [2.5, None, 1, None, 1.7]
            if metric_data == self.TEST_2_DATA:
                return [3.0, None, None, None, None]
            if metric_data == self.TEST_3_DATA:
                return [None, None, None, None, None]
            if metric_data == self.TEST_4_DATA:
                return [3.0, 1.5, 1.0, None, 1.5]
            if metric_data == self.TEST_5_DATA:
                return [None, None, 1.0, None, None]

        run_and_assert_calculate_alarm_state(
            mock_metric_alarm_details, mock_collect_metric_data, expected_calls, expected_state
        )

    @pytest.mark.parametrize(
        "initial_state,expected_state,expected_calls,treat_missing,metric_data",
        [
            # 0 - X - X
            ("OK", "ALARM", 1, "missing", TEST_1_M_OF_N),
            ("OK", "ALARM", 1, "ignore", TEST_1_M_OF_N),
            ("OK", "ALARM", 1, "breaching", TEST_1_M_OF_N),
            ("OK", "ALARM", 1, "notBreaching", TEST_1_M_OF_N),
            # 0 0 X 0 X
            ("OK", "ALARM", 1, "missing", TEST_2_M_OF_N),
            ("OK", "ALARM", 1, "ignore", TEST_2_M_OF_N),
            ("OK", "ALARM", 1, "breaching", TEST_2_M_OF_N),
            ("OK", "ALARM", 1, "notBreaching", TEST_2_M_OF_N),
            # 0 - X - -
            ("INSUFFICIENT_DATA", "OK", 1, "missing", TEST_3_M_OF_N),
            ("INSUFFICIENT_DATA", "OK", 1, "ignore", TEST_3_M_OF_N),
            ("INSUFFICIENT_DATA", "ALARM", 1, "breaching", TEST_3_M_OF_N),
            ("INSUFFICIENT_DATA", "OK", 1, "notBreaching", TEST_3_M_OF_N),
            # - - - - 0
            ("INSUFFICIENT_DATA", "OK", 1, "missing", TEST_4_M_OF_N),
            ("INSUFFICIENT_DATA", "OK", 1, "ignore", TEST_4_M_OF_N),
            ("INSUFFICIENT_DATA", "ALARM", 1, "breaching", TEST_4_M_OF_N),
            ("INSUFFICIENT_DATA", "OK", 1, "notBreaching", TEST_4_M_OF_N),
            # - - - X -
            ("INSUFFICIENT_DATA", "ALARM", 1, "missing", TEST_5_M_OF_N),
            ("INSUFFICIENT_DATA", "INSUFFICIENT_DATA", 0, "ignore", TEST_5_M_OF_N),
            ("INSUFFICIENT_DATA", "ALARM", 1, "breaching", TEST_5_M_OF_N),
            ("INSUFFICIENT_DATA", "OK", 1, "notBreaching", TEST_5_M_OF_N),
        ],
    )
    def test_calculate_alarm_state_2_out_of_3(
        self, initial_state, expected_state, expected_calls, treat_missing, metric_data
    ):
        """
        Tests Table 2 depicted in the docs: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html#alarm-evaluation
        Datapoints to Alarm = 2 and Evaluation Periods = 3
        Cloudwatch uses 5 latest datapoints for evaluation:
        0 = ok
        X = breaking threshold
        - = no data available
        |Test          | Data points  | MISSING          | IGNORE      | BREACHING | NOT BREACHING | # missing datapoints |
        |--------------|--------------|------------------|-------------|-----------|---------------| ---------------------|
        |TEST_1_M_OF_N | 0 - X - X    | ALARM            | ALARM       | ALARM     | ALARM         | 0                    |
        |TEST_2_M_OF_N | 0 0 X 0 X    | ALARM            | ALARM       | ALARM     | ALARM         | 0                    |
        |TEST_3_M_OF_N | 0 - X - -    | OK               | OK          | ALARM     | OK            | 1                    |
        |TEST_4_M_OF_N | - - - - 0    | OK               | OK          | ALARM     | OK            | 2                    |
        |TEST_5_M_OF_N | - - - X -    | ALARM            | Retain state| ALARM     | OK            | 2 -> Premature alarm |
        """

        def mock_metric_alarm_details(alarm_arn):
            details = {
                "AlarmName": "test-alarm",
                "StateValue": initial_state,
                "TreatMissingData": treat_missing,
                "DatapointsToAlarm": 2,
                "EvaluationPeriods": 3,
                "Period": 5,
                "ComparisonOperator": "LessThanThreshold",
                "Threshold": 2,
            }
            return details

        def mock_collect_metric_data(alarm_details, client):
            if metric_data == self.TEST_1_M_OF_N:
                return [2.5, None, 1, None, 1.7]
            if metric_data == self.TEST_2_M_OF_N:
                return [3.0, 4.0, 1.0, 3.5, 1.5]
            if metric_data == self.TEST_3_M_OF_N:
                return [4.0, None, 1.2, None, None]
            if metric_data == self.TEST_4_M_OF_N:
                return [None, None, None, None, 8]
            if metric_data == self.TEST_5_M_OF_N:
                return [None, None, None, 1.0, None]

        run_and_assert_calculate_alarm_state(
            mock_metric_alarm_details, mock_collect_metric_data, expected_calls, expected_state
        )

    def test_calculate_alarm_state_with_datapoints_value_zero(self):
        def mock_metric_alarm_details(alarm_arn):
            details = {
                "AlarmName": "test-alarm",
                "StateValue": "OK",
                "TreatMissingData": "notBreaching",
                "EvaluationPeriods": 1,
                "Period": 5,
                "ComparisonOperator": "LessThanThreshold",
                "Threshold": 1,
            }
            return details

        def mock_collect_metric_data(alarm_details, client):
            return [0.0, None, 0.0]

        run_and_assert_calculate_alarm_state(
            mock_metric_alarm_details, mock_collect_metric_data, 1, "ALARM"
        )


def run_and_assert_calculate_alarm_state(
    mock_metric_alarm_details, mock_collect_metric_data, expected_calls, expected_state
):
    mock_client = Mock()

    def mock_cloudwatch_client(alarm_arn):
        return mock_client

    patches = Patches(
        [
            Patch.function(
                alarm_scheduler.get_metric_alarm_details_for_alarm_arn,
                mock_metric_alarm_details,
                pass_target=False,
            ),
            Patch.function(
                alarm_scheduler.get_cloudwatch_client_for_region_of_alarm,
                mock_cloudwatch_client,
                pass_target=False,
            ),
            Patch.function(
                alarm_scheduler.collect_metric_data,
                mock_collect_metric_data,
                pass_target=False,
            ),
        ]
    )

    with patches:
        alarm_scheduler.calculate_alarm_state("helloworld")
        assert len(mock_client.mock_calls) == expected_calls
        if expected_calls != 0:
            expected_calls = [
                call.set_alarm_state(
                    AlarmName="test-alarm",
                    StateValue=expected_state,
                    StateReason=ANY,
                    StateReasonData=ANY,
                )
            ]
            mock_client.assert_has_calls(expected_calls)
