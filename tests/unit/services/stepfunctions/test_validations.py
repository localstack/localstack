from localstack.services.stepfunctions.provider import StepFunctionsProvider


class TestValidations:
    def test_state_machine_arn_with_periods(self):
        # will NOT throw an exception if the ARN is valid
        StepFunctionsProvider._validate_state_machine_arn(
            "arn:aws:states:us-east-1:000000000000:stateMachine:MyStateMachine.uixsr0hpy"
        )

    def test_state_machine_execution_arn_with_periods(self):
        # will NOT throw an exception if the ARN is valid
        StepFunctionsProvider()._validate_state_machine_execution_arn(
            "arn:aws:states:us-east-1:000000000000:stateMachine:MyStateMachine.uixsr0hpy:my.execution"
        )
