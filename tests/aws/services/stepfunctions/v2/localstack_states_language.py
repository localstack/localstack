import json

from aws.services.stepfunctions.templates.services.services_templates import ServicesTemplates
from localstack.aws.api.lambda_ import Runtime
from localstack.services.stepfunctions.asl.parse.lsl_parser import LocalStackStateLanguageParser
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import await_execution_terminated
from localstack.utils.strings import short_uid


class TestLocalStackStatesLanguage:
    @markers.aws.only_localstack
    def test_map_template_anonymous_inner_task(
        self,
        aws_client,
        create_lambda_function,
    ):
        state_machine = LocalStackStateLanguageParser.parse("""
            MapState(names) = for name in jsonata($names) where
                process {
                    greet_result = lambda:invoke where
                      arguments {
                        FunctionName: "GreetingFunction",
                        Payload: {
                          full_name: jsonata("Hello " & $name)
                        }
                      }
                    greet_value = jsonata($greet_result.Payload)
                    return jsonata($greet_value)
                }
            user_names = ["John", "Lewis"]
            all_greetings = MapState(names = jsonata($user_names))
            return jsonata($all_greetings)
        """)
        definition = json.dumps(state_machine)

        sfn = aws_client.stepfunctions

        create_state_machine_response = sfn.create_state_machine(
            name=f"autogen-{short_uid()}",
            definition=definition,
            roleArn="arn:aws:iam::000000000000:role/dummy",
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]

        function_name = "GreetingFunction"
        create_lambda_function(
            func_name=function_name,
            handler_file=ServicesTemplates.LAMBDA_ID_FUNCTION,
            runtime=Runtime.python3_12,
        )

        execute_state_machine_response = sfn.start_execution(stateMachineArn=state_machine_arn)
        execution_arn = execute_state_machine_response["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )
        execution_history_response = sfn.get_execution_history(executionArn=execution_arn)
        assert "executionSucceededEventDetails" in execution_history_response["events"][-1]
        details = execution_history_response["events"][-1]["executionSucceededEventDetails"]
        assert "Hello John" in details["output"]
        assert "Hello Lewis" in details["output"]

    @markers.aws.only_localstack
    def test_map_anonymous_inner(
        self,
        aws_client,
        create_lambda_function,
    ):
        state_machine = LocalStackStateLanguageParser.parse("""
            LambdaGreet(first_name, last_name) = lambda:invoke where
              arguments {
                FunctionName: "GreetingFunction",
                Payload: {
                  full_name: jsonata($first_name & " " & $last_name)
                }
              }

            user_names = ["John", "Lewis"]
            all_greetings = for name in jsonata($user_names) where
                process {
                    greet_result = LambdaGreet(first_name=jsonata($name), last_name="value")
                    greet_value = jsonata($greet_result.Payload)
                    return jsonata($greet_value)
                }
            return jsonata($all_greetings)
        """)
        definition = json.dumps(state_machine)

        sfn = aws_client.stepfunctions

        create_state_machine_response = sfn.create_state_machine(
            name=f"autogen-{short_uid()}",
            definition=definition,
            roleArn="arn:aws:iam::000000000000:role/dummy",
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]

        function_name = "GreetingFunction"
        create_lambda_function(
            func_name=function_name,
            handler_file=ServicesTemplates.LAMBDA_ID_FUNCTION,
            runtime=Runtime.python3_12,
        )

        execute_state_machine_response = sfn.start_execution(stateMachineArn=state_machine_arn)
        execution_arn = execute_state_machine_response["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )
        execution_history_response = sfn.get_execution_history(executionArn=execution_arn)
        assert "executionSucceededEventDetails" in execution_history_response["events"][-1]
        details = execution_history_response["events"][-1]["executionSucceededEventDetails"]
        assert "John" in details["output"]
        assert "Lewis" in details["output"]

    @markers.aws.only_localstack
    def test_assign_invoke_succeed(
        self,
        aws_client,
        create_lambda_function,
    ):
        state_machine = LocalStackStateLanguageParser.parse("""
            LambdaGreet(first_name, last_name) = lambda:invoke where
              arguments {
                FunctionName: "GreetingFunction",
                Payload: {
                  full_name: jsonata($first_name & " " & $last_name)
                }
              }

            user_name = "John"
            user_surname = "Smith"
            greeting_output = LambdaGreet(
                first_name=jsonata($user_name),
                last_name=jsonata($user_surname)
            )
            payload_value = jsonata($greeting_output.Payload)
            return jsonata($payload_value)
        """)
        definition = json.dumps(state_machine)

        sfn = aws_client.stepfunctions

        create_state_machine_response = sfn.create_state_machine(
            name=f"autogen-{short_uid()}",
            definition=definition,
            roleArn="arn:aws:iam::000000000000:role/dummy",
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]

        function_name = "GreetingFunction"
        create_lambda_function(
            func_name=function_name,
            handler_file=ServicesTemplates.LAMBDA_ID_FUNCTION,
            runtime=Runtime.python3_12,
        )

        execute_state_machine_response = sfn.start_execution(stateMachineArn=state_machine_arn)
        execution_arn = execute_state_machine_response["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )
        execution_history_response = sfn.get_execution_history(executionArn=execution_arn)
        assert "executionSucceededEventDetails" in execution_history_response["events"][-1]
        details = execution_history_response["events"][-1]["executionSucceededEventDetails"]
        assert "John Smith" in details["output"]

    @markers.aws.only_localstack
    def test_assign_and_invoke(
        self,
        aws_client,
        create_lambda_function,
    ):
        state_machine = LocalStackStateLanguageParser.parse("""
            LambdaGreet(first_name, last_name) = lambda:invoke where
              arguments {
                FunctionName: "GreetingFunction",
                Payload: {
                  full_name: jsonata($first_name & " " & $last_name)
                }
              }
            user_name = "John"
            user_surname = "Smith"
            LambdaGreet(
                first_name=jsonata($user_name),
                last_name=jsonata($user_surname)
            )
        """)
        definition = json.dumps(state_machine)

        sfn = aws_client.stepfunctions

        create_state_machine_response = sfn.create_state_machine(
            name=f"autogen-{short_uid()}",
            definition=definition,
            roleArn="arn:aws:iam::000000000000:role/dummy",
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]

        function_name = "GreetingFunction"
        create_lambda_function(
            func_name=function_name,
            handler_file=ServicesTemplates.LAMBDA_RETURN_DECORATED_INPUT,
            runtime=Runtime.python3_12,
        )

        execute_state_machine_response = sfn.start_execution(stateMachineArn=state_machine_arn)
        execution_arn = execute_state_machine_response["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )
        execution_history_response = sfn.get_execution_history(executionArn=execution_arn)
        assert "executionSucceededEventDetails" in execution_history_response["events"][-1]
        details = execution_history_response["events"][-1]["executionSucceededEventDetails"]
        assert "John Smith" in details["output"]

    @markers.aws.only_localstack
    def test_assign_and_succeed(self, aws_client):
        state_machine = LocalStackStateLanguageParser.parse("""
            WorkflowSucceeded(value) = return jsonata($value)
            output_message = jsonata("Hello" & " " & "World!")
            WorkflowSucceeded(value = jsonata($output_message))
        """)
        definition = json.dumps(state_machine)

        sfn = aws_client.stepfunctions

        create_state_machine_response = sfn.create_state_machine(
            name=f"autogen-{short_uid()}",
            definition=definition,
            roleArn="arn:aws:iam::000000000000:role/dummy",
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]

        execute_state_machine_response = sfn.start_execution(stateMachineArn=state_machine_arn)
        execution_arn = execute_state_machine_response["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )
        execution_history_response = sfn.get_execution_history(executionArn=execution_arn)
        assert "executionSucceededEventDetails" in execution_history_response["events"][-1]
        details = execution_history_response["events"][-1]["executionSucceededEventDetails"]
        assert "Hello World" in details["output"]

    @markers.aws.only_localstack
    def test_succeed_template(self, aws_client):
        state_machine = LocalStackStateLanguageParser.parse("""
            WorkflowSucceeded(value) = return jsonata($value)
            WorkflowSucceeded(value = {"message": "string-literal"})
        """)
        definition = json.dumps(state_machine)

        sfn = aws_client.stepfunctions

        create_state_machine_response = sfn.create_state_machine(
            name=f"autogen-{short_uid()}",
            definition=definition,
            roleArn="arn:aws:iam::000000000000:role/dummy",
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]

        execute_state_machine_response = sfn.start_execution(stateMachineArn=state_machine_arn)
        execution_arn = execute_state_machine_response["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )
        execution_history_response = sfn.get_execution_history(executionArn=execution_arn)
        assert "executionSucceededEventDetails" in execution_history_response["events"][-1]
        details = execution_history_response["events"][-1]["executionSucceededEventDetails"]
        assert details["output"] == '{"message":"string-literal"}'

    @markers.aws.only_localstack
    def test_succeed_inplace(self, aws_client):
        state_machine = LocalStackStateLanguageParser.parse("""
            WorkflowSucceeded as return jsonata('string' & ' ' & 'literal')
        """)
        definition = json.dumps(state_machine)

        sfn = aws_client.stepfunctions

        create_state_machine_response = sfn.create_state_machine(
            name=f"autogen-{short_uid()}",
            definition=definition,
            roleArn="arn:aws:iam::000000000000:role/dummy",
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]

        execute_state_machine_response = sfn.start_execution(stateMachineArn=state_machine_arn)
        execution_arn = execute_state_machine_response["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )
        execution_history_response = sfn.get_execution_history(executionArn=execution_arn)
        assert "executionSucceededEventDetails" in execution_history_response["events"][-1]
        details = execution_history_response["events"][-1]["executionSucceededEventDetails"]
        assert details["output"] == '"string literal"'

    @markers.aws.only_localstack
    def test_succeed_anonymous_inplace(self, aws_client):
        state_machine = LocalStackStateLanguageParser.parse("""
            return jsonata('string' & ' ' & 'literal')
        """)
        definition = json.dumps(state_machine)

        sfn = aws_client.stepfunctions

        create_state_machine_response = sfn.create_state_machine(
            name=f"autogen-{short_uid()}",
            definition=definition,
            roleArn="arn:aws:iam::000000000000:role/dummy",
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]

        execute_state_machine_response = sfn.start_execution(stateMachineArn=state_machine_arn)
        execution_arn = execute_state_machine_response["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )
        execution_history_response = sfn.get_execution_history(executionArn=execution_arn)
        assert "executionSucceededEventDetails" in execution_history_response["events"][-1]
        details = execution_history_response["events"][-1]["executionSucceededEventDetails"]
        assert details["output"] == '"string literal"'

    @markers.aws.only_localstack
    def test_lambda_invoke_anonymous_inplace(
        self,
        aws_client,
        create_lambda_function,
    ):
        state_machine = LocalStackStateLanguageParser.parse("""
            lambda:invoke where
              arguments {
                FunctionName: "GreetingFunction",
                Payload: {
                  full_name: jsonata('John' & " " & 'Smith')
                }
              }
        """)
        definition = json.dumps(state_machine)

        sfn = aws_client.stepfunctions

        create_state_machine_response = sfn.create_state_machine(
            name=f"autogen-{short_uid()}",
            definition=definition,
            roleArn="arn:aws:iam::000000000000:role/dummy",
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]

        function_name = "GreetingFunction"
        create_lambda_function(
            func_name=function_name,
            handler_file=ServicesTemplates.LAMBDA_RETURN_DECORATED_INPUT,
            runtime=Runtime.python3_12,
        )

        execute_state_machine_response = sfn.start_execution(stateMachineArn=state_machine_arn)
        execution_arn = execute_state_machine_response["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )
        execution_history_response = sfn.get_execution_history(executionArn=execution_arn)
        assert "executionSucceededEventDetails" in execution_history_response["events"][-1]

    @markers.aws.only_localstack
    def test_lambda_invoke_named_inplace(
        self,
        aws_client,
        create_lambda_function,
    ):
        state_machine = LocalStackStateLanguageParser.parse("""
            LambdaGreet as lambda:invoke where
              arguments {
                FunctionName: "GreetingFunction",
                Payload: {
                  full_name: jsonata('John' & " " & 'Smith')
                }
              }
        """)
        definition = json.dumps(state_machine)

        sfn = aws_client.stepfunctions

        create_state_machine_response = sfn.create_state_machine(
            name=f"autogen-{short_uid()}",
            definition=definition,
            roleArn="arn:aws:iam::000000000000:role/dummy",
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]

        function_name = "GreetingFunction"
        create_lambda_function(
            func_name=function_name,
            handler_file=ServicesTemplates.LAMBDA_RETURN_DECORATED_INPUT,
            runtime=Runtime.python3_12,
        )

        execute_state_machine_response = sfn.start_execution(stateMachineArn=state_machine_arn)
        execution_arn = execute_state_machine_response["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )
        execution_history_response = sfn.get_execution_history(executionArn=execution_arn)
        assert "executionSucceededEventDetails" in execution_history_response["events"][-1]

    @markers.aws.only_localstack
    def test_lambda_invoke(
        self,
        aws_client,
        create_lambda_function,
    ):
        state_machine = LocalStackStateLanguageParser.parse("""
            LambdaGreet(first_name, last_name) = lambda:invoke where
              arguments {
                FunctionName: "GreetingFunction",
                Payload: {
                  full_name: jsonata($first_name & " " & $last_name)
                }
              }

            LambdaGreet(first_name="John", last_name="Smith")
            LambdaGreet(first_name="second", last_name="s") # create a copy of the target on demand!
        """)
        definition = json.dumps(state_machine)

        sfn = aws_client.stepfunctions

        create_state_machine_response = sfn.create_state_machine(
            name=f"autogen-{short_uid()}",
            definition=definition,
            roleArn="arn:aws:iam::000000000000:role/dummy",
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]

        function_name = "GreetingFunction"
        create_lambda_function(
            func_name=function_name,
            handler_file=ServicesTemplates.LAMBDA_RETURN_DECORATED_INPUT,
            runtime=Runtime.python3_12,
        )

        execute_state_machine_response = sfn.start_execution(stateMachineArn=state_machine_arn)
        execution_arn = execute_state_machine_response["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )
        execution_history_response = sfn.get_execution_history(executionArn=execution_arn)
        assert "executionSucceededEventDetails" in execution_history_response["events"][-1]
