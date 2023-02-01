# TODO: Temporary collection of state machine templates. Options:
#   - Enable dumping of Component objects for machine definitions.
#   - Create sub-templates for state machine sub productions.
from localstack.utils.json import clone


class Templates:
    BASE_INVALID_DER = {
        "Comment": "BASE_INVALID_DER",
        "StartAt": "State_1",
    }

    BASE_PASS_RESULT = {
        "Comment": "BASE_PASS_RESULT",
        "StartAt": "State_1",
        "States": {
            "State_1": {
                "Type": "Pass",
                "Result": {
                    "Arg1": "argument1",
                },
                "End": True,
            }
        },
    }

    BASE_TASK_SEQ_2 = {
        "Comment": "Hello World example",
        "StartAt": "State_1",
        "States": {
            "State_1": {"Type": "Task", "Resource": "__tbd__", "Next": "State_2"},
            "State_2": {
                "Type": "Task",
                "Resource": "__tbd__",
                "ResultPath": "$.result_value",
                "End": True,
            },
        },
    }

    WAIT_1_MIN = {
        "Comment": "WAIT_10_SEC",
        "StartAt": "State_1",
        "States": {
            "State_1": {"Type": "Wait", "Seconds": 60, "Next": "State_2"},
            "State_2": {
                "Type": "Pass",
                "Result": {
                    "Arg1": "argument1",
                },
                "End": True,
            },
        },
    }

    @staticmethod
    def copy_of(template: dict) -> dict:
        return clone(template)
