import json

import pytest

from localstack.services.stepfunctions.asl.static_analyser.accessible_states_static_analyser import (
    AccessibleStatesStaticAnalyser,
)

NO_MISSING_TARGET_SINGLE_SCOPE = json.dumps(
    {
        "StartAt": "pass1",
        "States": {
            "pass1": {"Type": "Pass", "Next": "pass2"},
            "pass2": {"Type": "Pass", "End": True},
        },
    }
)

NO_MISSING_TARGET_PARALLEL_SCOPE = json.dumps(
    {
        "StartAt": "pass1",
        "States": {
            "pass1": {"Type": "Pass", "Next": "pass2"},
            "pass2": {"Type": "Pass", "Next": "parallel"},
            "parallel": {
                "Type": "Parallel",
                "Branches": [
                    {"StartAt": "pass1p", "States": {"pass1p": {"Type": "Pass", "End": True}}},
                    {"StartAt": "pass2p", "States": {"pass2p": {"Type": "Pass", "End": True}}},
                ],
                "Next": "pass3",
            },
            "pass3": {"Type": "Pass", "End": True},
        },
    }
)

MISSING_TARGET_SINGLE_SCOPE = json.dumps(
    {
        "StartAt": "pass1",
        "States": {
            "pass1": {"Type": "Pass", "Next": "pass3"},
            "pass2": {"Type": "Pass", "End": True},
        },
    }
)

MISSING_TARGET_ROOT_SCOPE_UNREACHABLE_FROM_PARALLEL = json.dumps(
    {
        "StartAt": "pass1",
        "States": {
            "pass1": {"Type": "Pass", "Next": "pass2"},
            "pass2": {"Type": "Pass", "Next": "parallel"},
            "parallel": {
                "Type": "Parallel",
                "Branches": [
                    {"StartAt": "pass1p", "States": {"pass1p": {"Type": "Pass", "Next": "pass2"}}},
                    {"StartAt": "pass2p", "States": {"pass2p": {"Type": "Pass", "End": True}}},
                ],
                "End": True,
            },
        },
    }
)

MISSING_TARGET_OTHER_BRANCH_SCOPE_UNREACHABLE_FROM_PARALLEL = json.dumps(
    {
        "StartAt": "pass1",
        "States": {
            "pass1": {"Type": "Pass", "Next": "pass2"},
            "pass2": {"Type": "Pass", "Next": "parallel"},
            "parallel": {
                "Type": "Parallel",
                "Branches": [
                    {"StartAt": "pass1p", "States": {"pass1p": {"Type": "Pass", "Next": "pass2p"}}},
                    {"StartAt": "pass2p", "States": {"pass2p": {"Type": "Pass", "End": True}}},
                ],
                "End": True,
            },
        },
    }
)


class TestAccessibleStatesStaticAnalyser:
    @pytest.mark.parametrize(
        "definition",
        [
            NO_MISSING_TARGET_SINGLE_SCOPE,
            NO_MISSING_TARGET_PARALLEL_SCOPE,
        ],
        ids=[
            "NO_MISSING_TARGET_SINGLE_SCOPE",
            "NO_MISSING_TARGET_PARALLEL_SCOPE",
        ],
    )
    def test_no_missing_target(self, definition):
        AccessibleStatesStaticAnalyser().analyse(definition=definition)

    @pytest.mark.parametrize(
        "definition,expected_messages",
        [
            (
                MISSING_TARGET_SINGLE_SCOPE,
                [
                    "MISSING_TRANSITION_TARGET: Missing Next target: pass3 at FIXME",
                    "MISSING_TRANSITION_TARGET: State pass2 is not reachable. at FIXME",
                ],
            ),
            (
                MISSING_TARGET_ROOT_SCOPE_UNREACHABLE_FROM_PARALLEL,
                ["MISSING_TRANSITION_TARGET: Missing Next target: pass2 at FIXME"],
            ),
            (
                MISSING_TARGET_OTHER_BRANCH_SCOPE_UNREACHABLE_FROM_PARALLEL,
                ["MISSING_TRANSITION_TARGET: Missing Next target: pass2p at FIXME"],
            ),
        ],
        ids=[
            "MISSING_TARGET_SINGLE_SCOPE",
            "MISSING_TARGET_ROOT_SCOPE_UNREACHABLE_FROM_PARALLEL",
            "MISSING_TARGET_OTHER_BRANCH_SCOPE_UNREACHABLE_FROM_PARALLEL",
        ],
    )
    def test_missing_target(self, definition, expected_messages):
        with pytest.raises(ValueError) as analysis_err:
            AccessibleStatesStaticAnalyser().analyse(definition=definition)
        error_msg = str(analysis_err.value)
        TestAccessibleStatesStaticAnalyser._assert_error_msg_prefix(error_msg)
        for expected_message in expected_messages:
            assert expected_message in error_msg

    @staticmethod
    def _assert_error_msg_prefix(msg):
        assert msg.startswith("Invalid State Machine Definition: ")
