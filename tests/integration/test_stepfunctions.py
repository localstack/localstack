import os
import json
import unittest
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import load_file, clone, retry, short_uid
from localstack.services.awslambda import lambda_api
from .lambdas import lambda_environment

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_environment.py')
TEST_LAMBDA_ECHO = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_echo.py')
TEST_LAMBDA_NAME_1 = 'lambda_sfn_1'
TEST_LAMBDA_NAME_2 = 'lambda_sfn_2'
TEST_RESULT_VALUE = 'testresult1'
STATE_MACHINE_BASIC = {
    'Comment': 'Hello World example',
    'StartAt': 'step1',
    'States': {
        'step1': {
            'Type': 'Task',
            'Resource': '__tbd__',
            'Next': 'step2'
        },
        'step2': {
            'Type': 'Task',
            'Resource': '__tbd__',
            'ResultPath': '$.result_value',
            'End': True
        }
    }
}
TEST_LAMBDA_NAME_3 = 'lambda_map_sfn_3'
STATE_MACHINE_MAP = {
    'Comment': 'Hello Map State',
    'StartAt': 'ExampleMapState',
    'States': {
        'ExampleMapState': {
            'Type': 'Map',
            'Iterator': {
                'StartAt': 'CallLambda',
                'States': {
                    'CallLambda': {
                        'Type': 'Task',
                        'Resource': '__tbd__',
                        'End': True
                    }
                }
            },
            'End': True
        }
    }
}
TEST_LAMBDA_NAME_4 = 'lambda_choice_sfn_4'
STATE_MACHINE_CHOICE = {
    'StartAt': 'CheckValues',
    'States': {
        'CheckValues': {
            'Type': 'Choice',
            'Choices': [
                {
                    'And': [{
                        'Variable': '$.x',
                        'IsPresent': True
                    }, {
                        'Variable': '$.y',
                        'IsPresent': True
                    }],
                    'Next': 'Add'
                }
            ],
            'Default': 'MissingValue'
        },
        'MissingValue': {
            'Type': 'Fail',
            'Cause': 'test'
        },
        'Add': {
            'Type': 'Task',
            'Resource': '__tbd__',
            'ResultPath': '$.added',
            'TimeoutSeconds': 10,
            'End': True
        }
    }
}
STATE_MACHINE_CATCH = {
    'StartAt': 'Start',
    'States': {
        'Start': {
            'Type': 'Task',
            'Resource': 'arn:aws:states:::lambda:invoke',
            'Parameters': {
                'FunctionName': '__tbd__',
                'Payload': {lambda_environment.MSG_BODY_RAISE_ERROR_FLAG: 1}
            },
            'Catch': [{
                'ErrorEquals': [
                    'InvocationException',
                    'Lambda.Unknown',
                    'ValueError'
                ],
                'ResultPath': '$.error',
                'Next': 'ErrorHandler'
            }],
            'Next': 'Final'
        },
        'ErrorHandler': {
            'Type': 'Task',
            'Resource': '__tbd__',
            'ResultPath': '$.handled',
            'Next': 'Final'
        },
        'Final': {
            'Type': 'Task',
            'Resource': '__tbd__',
            'ResultPath': '$.final',
            'End': True
        }
    }
}
TEST_LAMBDA_NAME_5 = 'lambda_intrinsic_sfn_5'
STATE_MACHINE_INTRINSIC_FUNCS = {
    'StartAt': 'state0',
    'States': {
        'state0': {
            'Type': 'Pass',
            'Result': {
                'v1': 1,
                'v2': 'v2'
            },
            'Next': 'state1'
        },
        'state1': {
            'Type': 'Pass',
            'Parameters': {
                'lambda_params': {
                    'FunctionName': '__tbd__',
                    'Payload': {'values.$': 'States.Array($.v1, $.v2)'}
                }
            },
            'Next': 'state2'
        },
        'state2': {
            'Type': 'Task',
            'Resource': 'arn:aws:states:::lambda:invoke',
            'Parameters': {
                'FunctionName.$': '$.lambda_params.FunctionName',
                'Payload.$': 'States.StringToJson(States.JsonToString($.lambda_params.Payload))'
            },
            'Next': 'state3'
        },
        'state3': {
            'Type': 'Task',
            'Resource': '__tbd__',
            'ResultSelector': {
                'payload.$': '$'
            },
            'ResultPath': '$.result_value',
            'End': True
        }
    }
}


class TestStateMachine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.lambda_client = aws_stack.connect_to_service('lambda')
        cls.s3_client = aws_stack.connect_to_service('s3')
        cls.sfn_client = aws_stack.connect_to_service('stepfunctions')

        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON),
            get_content=True
        )
        zip_file2 = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_ECHO),
            get_content=True
        )
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_1,
            zip_file=zip_file,
            envvars={'Hello': TEST_RESULT_VALUE}
        )
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_2,
            zip_file=zip_file,
            envvars={'Hello': TEST_RESULT_VALUE}
        )
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_3,
            zip_file=zip_file,
            envvars={'Hello': 'Replace Value'}
        )
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_4,
            zip_file=zip_file,
            envvars={'Hello': TEST_RESULT_VALUE}
        )
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_5,
            zip_file=zip_file2
        )

    @classmethod
    def tearDownClass(cls):
        cls.lambda_client.delete_function(FunctionName=TEST_LAMBDA_NAME_1)
        cls.lambda_client.delete_function(FunctionName=TEST_LAMBDA_NAME_2)
        cls.lambda_client.delete_function(FunctionName=TEST_LAMBDA_NAME_3)
        cls.lambda_client.delete_function(FunctionName=TEST_LAMBDA_NAME_4)

    def test_create_choice_state_machine(self):
        state_machines_before = self.sfn_client.list_state_machines()['stateMachines']
        role_arn = aws_stack.role_arn('sfn_role')

        definition = clone(STATE_MACHINE_CHOICE)
        lambda_arn_4 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_4)
        definition['States']['Add']['Resource'] = lambda_arn_4
        definition = json.dumps(definition)
        sm_name = 'choice-%s' % short_uid()
        result = self.sfn_client.create_state_machine(name=sm_name, definition=definition, roleArn=role_arn)

        # assert that the SM has been created
        self.assert_machine_created(state_machines_before)

        # run state machine
        sm_arn = self.get_machine_arn(sm_name)
        input = {'x': '1', 'y': '2'}
        result = self.sfn_client.start_execution(stateMachineArn=sm_arn, input=json.dumps(input))
        self.assertTrue(result.get('executionArn'))

        # define expected output
        test_output = {**input, 'added': {'Hello': TEST_RESULT_VALUE}}

        def check_result():
            result = self._get_execution_results(sm_arn)
            self.assertEqual(result, test_output)

        # assert that the result is correct
        retry(check_result, sleep=2, retries=10)

        # clean up
        self.cleanup(sm_arn, state_machines_before)

    def test_create_run_map_state_machine(self):
        names = ['Bob', 'Meg', 'Joe']
        test_input = [{'map': name} for name in names]
        test_output = [{'Hello': name} for name in names]
        state_machines_before = self.sfn_client.list_state_machines()['stateMachines']

        role_arn = aws_stack.role_arn('sfn_role')
        definition = clone(STATE_MACHINE_MAP)
        lambda_arn_3 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_3)
        definition['States']['ExampleMapState']['Iterator']['States']['CallLambda']['Resource'] = lambda_arn_3
        definition = json.dumps(definition)
        sm_name = 'map-%s' % short_uid()
        result = self.sfn_client.create_state_machine(name=sm_name, definition=definition, roleArn=role_arn)

        # assert that the SM has been created
        self.assert_machine_created(state_machines_before)

        # run state machine
        sm_arn = self.get_machine_arn(sm_name)
        lambda_api.LAMBDA_EXECUTOR.function_invoke_times.clear()
        result = self.sfn_client.start_execution(stateMachineArn=sm_arn, input=json.dumps(test_input))
        self.assertTrue(result.get('executionArn'))

        def check_invocations():
            self.assertIn(lambda_arn_3, lambda_api.LAMBDA_EXECUTOR.function_invoke_times)
            # assert that the result is correct
            result = self._get_execution_results(sm_arn)
            self.assertEqual(result, test_output)

        # assert that the lambda has been invoked by the SM execution
        retry(check_invocations, sleep=1, retries=10)

        # clean up
        self.cleanup(sm_arn, state_machines_before)

    def test_create_run_state_machine(self):
        state_machines_before = self.sfn_client.list_state_machines()['stateMachines']

        # create state machine
        role_arn = aws_stack.role_arn('sfn_role')
        definition = clone(STATE_MACHINE_BASIC)
        lambda_arn_1 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_1)
        lambda_arn_2 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_2)
        definition['States']['step1']['Resource'] = lambda_arn_1
        definition['States']['step2']['Resource'] = lambda_arn_2
        definition = json.dumps(definition)
        sm_name = 'basic-%s' % short_uid()
        result = self.sfn_client.create_state_machine(name=sm_name, definition=definition, roleArn=role_arn)

        # assert that the SM has been created
        self.assert_machine_created(state_machines_before)

        # run state machine
        sm_arn = self.get_machine_arn(sm_name)
        lambda_api.LAMBDA_EXECUTOR.function_invoke_times.clear()
        result = self.sfn_client.start_execution(stateMachineArn=sm_arn)
        self.assertTrue(result.get('executionArn'))

        def check_invocations():
            self.assertIn(lambda_arn_1, lambda_api.LAMBDA_EXECUTOR.function_invoke_times)
            self.assertIn(lambda_arn_2, lambda_api.LAMBDA_EXECUTOR.function_invoke_times)
            # assert that the result is correct
            result = self._get_execution_results(sm_arn)
            self.assertEqual(result['result_value'], {'Hello': TEST_RESULT_VALUE})

        # assert that the lambda has been invoked by the SM execution
        retry(check_invocations, sleep=0.7, retries=25)

        # clean up
        self.cleanup(sm_arn, state_machines_before)

    def test_try_catch_state_machine(self):
        state_machines_before = self.sfn_client.list_state_machines()['stateMachines']

        # create state machine
        role_arn = aws_stack.role_arn('sfn_role')
        definition = clone(STATE_MACHINE_CATCH)
        lambda_arn_1 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_1)
        lambda_arn_2 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_2)
        definition['States']['Start']['Parameters']['FunctionName'] = lambda_arn_1
        definition['States']['ErrorHandler']['Resource'] = lambda_arn_2
        definition['States']['Final']['Resource'] = lambda_arn_2
        definition = json.dumps(definition)
        sm_name = 'catch-%s' % short_uid()
        result = self.sfn_client.create_state_machine(name=sm_name, definition=definition, roleArn=role_arn)

        # run state machine
        sm_arn = self.get_machine_arn(sm_name)
        lambda_api.LAMBDA_EXECUTOR.function_invoke_times.clear()
        result = self.sfn_client.start_execution(stateMachineArn=sm_arn)
        self.assertTrue(result.get('executionArn'))

        def check_invocations():
            self.assertIn(lambda_arn_1, lambda_api.LAMBDA_EXECUTOR.function_invoke_times)
            self.assertIn(lambda_arn_2, lambda_api.LAMBDA_EXECUTOR.function_invoke_times)
            # assert that the result is correct
            result = self._get_execution_results(sm_arn)
            self.assertEqual(result.get('handled'), {'Hello': TEST_RESULT_VALUE})

        # assert that the lambda has been invoked by the SM execution
        retry(check_invocations, sleep=1, retries=10)

        # clean up
        self.cleanup(sm_arn, state_machines_before)

    def test_intrinsic_functions(self):
        state_machines_before = self.sfn_client.list_state_machines()['stateMachines']

        # create state machine
        role_arn = aws_stack.role_arn('sfn_role')
        definition = clone(STATE_MACHINE_INTRINSIC_FUNCS)
        lambda_arn_1 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_5)
        lambda_arn_2 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_5)
        if isinstance(definition['States']['state1'].get('Parameters'), dict):
            definition['States']['state1']['Parameters']['lambda_params']['FunctionName'] = lambda_arn_1
            definition['States']['state3']['Resource'] = lambda_arn_2
        definition = json.dumps(definition)
        sm_name = 'intrinsic-%s' % short_uid()
        result = self.sfn_client.create_state_machine(name=sm_name, definition=definition, roleArn=role_arn)

        # run state machine
        sm_arn = self.get_machine_arn(sm_name)
        lambda_api.LAMBDA_EXECUTOR.function_invoke_times.clear()
        input = {}
        result = self.sfn_client.start_execution(stateMachineArn=sm_arn, input=json.dumps(input))
        self.assertTrue(result.get('executionArn'))

        def check_invocations():
            self.assertIn(lambda_arn_1, lambda_api.LAMBDA_EXECUTOR.function_invoke_times)
            self.assertIn(lambda_arn_2, lambda_api.LAMBDA_EXECUTOR.function_invoke_times)
            # assert that the result is correct
            result = self._get_execution_results(sm_arn)
            self.assertEqual(result.get('result_value'), {'payload': {'values': [1, 'v2']}})

        # assert that the lambda has been invoked by the SM execution
        retry(check_invocations, sleep=1, retries=10)

        # clean up
        self.cleanup(sm_arn, state_machines_before)

    def get_machine_arn(self, sm_name):
        state_machines = self.sfn_client.list_state_machines()['stateMachines']
        return [m['stateMachineArn'] for m in state_machines if m['name'] == sm_name][0]

    def assert_machine_created(self, state_machines_before):
        return self._assert_machine_instances(len(state_machines_before) + 1)

    def assert_machine_deleted(self, state_machines_before):
        return self._assert_machine_instances(len(state_machines_before))

    def cleanup(self, sm_arn, state_machines_before):
        self.sfn_client.delete_state_machine(stateMachineArn=sm_arn)
        self.assert_machine_deleted(state_machines_before)

    def _assert_machine_instances(self, expected_instances):
        def check():
            state_machines_after = self.sfn_client.list_state_machines()['stateMachines']
            self.assertEqual(len(state_machines_after), expected_instances)
            return state_machines_after
        return retry(check, sleep=1, retries=4)

    def _get_execution_results(self, sm_arn):
        response = self.sfn_client.list_executions(stateMachineArn=sm_arn)
        executions = sorted(response['executions'], key=lambda x: x['startDate'])
        execution = executions[-1]
        result = self.sfn_client.get_execution_history(executionArn=execution['executionArn'])
        events = sorted(result['events'], key=lambda event: event['timestamp'])
        result = json.loads(events[-1]['executionSucceededEventDetails']['output'])
        return result
