import json

import pytest
import yaml
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.aws.api.stepfunctions import HistoryEventList
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    await_execution_aborted,
    await_execution_success,
    await_execution_terminated,
    await_list_execution_status,
    await_on_execution_events,
    await_state_machine_listed,
    await_state_machine_not_listed,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.lambda_functions import lambda_functions
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate


@markers.snapshot.skip_snapshot_verify(paths=["$..tracingConfiguration"])
class TestSnfApi:
    @markers.aws.validated
    def test_create_delete_valid_sm(
        self,
        create_iam_role_for_sfn,
        create_lambda_function,
        create_state_machine,
        sfn_snapshot,
        aws_client,
    ):
        create_lambda_1 = create_lambda_function(
            handler_file=lambda_functions.BASE_ID_FUNCTION,
            func_name="id_function",
            runtime=Runtime.python3_12,
        )
        lambda_arn_1 = create_lambda_1["CreateFunctionResponse"]["FunctionArn"]

        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_TASK_SEQ_2)
        definition["States"]["State_1"]["Resource"] = lambda_arn_1
        definition["States"]["State_2"]["Resource"] = lambda_arn_1
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)

        state_machine_arn = creation_resp_1["stateMachineArn"]

        deletion_resp_1 = aws_client.stepfunctions.delete_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("deletion_resp_1", deletion_resp_1)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: add static analyser support.
            "$..Message",
            "$..message",
        ]
    )
    @markers.aws.validated
    def test_create_delete_invalid_sm(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_INVALID_DER)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"

        with pytest.raises(Exception) as resource_not_found:
            create_state_machine(name=sm_name, definition=definition_str, roleArn=snf_role_arn)
        sfn_snapshot.match("invalid_definition_1", resource_not_found.value.response)

    @markers.aws.validated
    def test_delete_nonexistent_sm(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)
        sm_name = f"statemachine_{short_uid()}"

        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        state_machine_arn: str = creation_resp_1["stateMachineArn"]

        sm_nonexistent_name = f"statemachine_{short_uid()}"
        sm_nonexistent_arn = state_machine_arn.replace(sm_name, sm_nonexistent_name)

        deletion_resp_1 = aws_client.stepfunctions.delete_state_machine(
            stateMachineArn=sm_nonexistent_arn
        )
        sfn_snapshot.match("deletion_resp_1", deletion_resp_1)

    @markers.aws.validated
    def test_describe_nonexistent_sm(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)
        sm_name = f"statemachine_{short_uid()}"

        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        state_machine_arn: str = creation_resp_1["stateMachineArn"]

        sm_nonexistent_name = f"statemachine_{short_uid()}"
        sm_nonexistent_arn = state_machine_arn.replace(sm_name, sm_nonexistent_name)
        sfn_snapshot.add_transformer(RegexTransformer(sm_nonexistent_arn, "sm_nonexistent_arn"))

        with pytest.raises(Exception) as exc:
            aws_client.stepfunctions.describe_state_machine(stateMachineArn=sm_nonexistent_arn)
        sfn_snapshot.match("describe_nonexistent_sm", exc.value)

    @markers.aws.validated
    def test_describe_sm_arn_containing_punctuation(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        # ARN will contain a punctuation symbol
        sm_name = f"state.machine_{short_uid()}"

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        sfn_snapshot.match("creation_resp", creation_resp)

        describe_resp = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=creation_resp["stateMachineArn"]
        )
        sfn_snapshot.match("describe_resp", describe_resp)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..exception_value"])
    def test_describe_invalid_arn_sm(self, sfn_snapshot, aws_client):
        with pytest.raises(Exception) as exc:
            aws_client.stepfunctions.describe_state_machine(stateMachineArn="not_a_valid_arn")
        sfn_snapshot.match(
            "exception", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

    @markers.aws.validated
    def test_create_exact_duplicate_sm(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)
        sm_name = f"statemachine_{short_uid()}"

        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)
        state_machine_arn_1 = creation_resp_1["stateMachineArn"]

        describe_resp_1 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn_1
        )
        sfn_snapshot.match("describe_resp_1", describe_resp_1)

        creation_resp_2 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_2, 1))
        sfn_snapshot.match("creation_resp_2", creation_resp_2)
        state_machine_arn_2 = creation_resp_2["stateMachineArn"]

        describe_resp_2 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn_2
        )
        sfn_snapshot.match("describe_resp_2", describe_resp_2)

        describe_resp_1_2 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn_1
        )
        sfn_snapshot.match("describe_resp_1_2", describe_resp_1_2)

    @markers.aws.validated
    def test_create_duplicate_definition_format_sm(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)
        sm_name = f"statemachine_{short_uid()}"

        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)
        state_machine_arn_1 = creation_resp_1["stateMachineArn"]

        describe_resp_1 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn_1
        )
        sfn_snapshot.match("describe_resp_1", describe_resp_1)

        definition_str_2 = json.dumps(definition, indent=4)
        with pytest.raises(Exception) as resource_not_found:
            create_state_machine(name=sm_name, definition=definition_str_2, roleArn=snf_role_arn)
        sfn_snapshot.match("already_exists_1", resource_not_found.value.response)

    @markers.aws.validated
    def test_create_duplicate_sm_name(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition_1 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str_1 = json.dumps(definition_1)
        sm_name = f"statemachine_{short_uid()}"

        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str_1, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)
        state_machine_arn_1 = creation_resp_1["stateMachineArn"]

        describe_resp_1 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn_1
        )
        sfn_snapshot.match("describe_resp_1", describe_resp_1)

        definition_2 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_2["States"]["State_1"]["Result"].update({"Arg2": "Argument2"})
        definition_str_2 = json.dumps(definition_2)

        with pytest.raises(Exception) as resource_not_found:
            create_state_machine(name=sm_name, definition=definition_str_2, roleArn=snf_role_arn)
        sfn_snapshot.match("already_exists_1", resource_not_found.value.response)

    @markers.aws.needs_fixing
    def test_list_sms(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        sm_names = [
            f"statemachine_1_{short_uid()}",
            f"statemachine_2_{short_uid()}",
            f"statemachine_3_{short_uid()}",
        ]
        state_machine_arns = list()

        for i, sm_name in enumerate(sm_names):
            creation_resp = create_state_machine(
                name=sm_name,
                definition=definition_str,
                roleArn=snf_role_arn,
            )
            sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, i))
            sfn_snapshot.match(f"creation_resp_{i}", creation_resp)
            state_machine_arn: str = creation_resp["stateMachineArn"]
            state_machine_arns.append(state_machine_arn)

            await_state_machine_listed(
                stepfunctions_client=aws_client.stepfunctions, state_machine_arn=state_machine_arn
            )

        lst_resp = aws_client.stepfunctions.list_state_machines()
        lst_resp_filter = [sm for sm in lst_resp["stateMachines"] if sm["name"] in sm_names]
        sfn_snapshot.match("lst_resp_filter", lst_resp_filter)

        for i, state_machine_arn in enumerate(state_machine_arns):
            deletion_resp = aws_client.stepfunctions.delete_state_machine(
                stateMachineArn=state_machine_arn
            )
            sfn_snapshot.match(f"deletion_resp_{i}", deletion_resp)

            await_state_machine_not_listed(
                stepfunctions_client=aws_client.stepfunctions, state_machine_arn=state_machine_arn
            )

        lst_resp = aws_client.stepfunctions.list_state_machines()
        lst_resp_filter = [sm for sm in lst_resp["stateMachines"] if sm["name"] in sm_names]
        sfn_snapshot.match("lst_resp_del_filter", lst_resp_filter)

    @markers.aws.needs_fixing
    def test_start_execution(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        sfn_snapshot.match("creation_resp", creation_resp)
        state_machine_arn = creation_resp["stateMachineArn"]

        exec_resp = aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn)
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        sfn_snapshot.match("exec_resp", exec_resp)
        execution_arn = exec_resp["executionArn"]

        await_execution_success(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )

        exec_list_resp = aws_client.stepfunctions.list_executions(stateMachineArn=state_machine_arn)
        sfn_snapshot.match("exec_list_resp", exec_list_resp)

        exec_hist_resp = aws_client.stepfunctions.get_execution_history(executionArn=execution_arn)
        sfn_snapshot.match("exec_hist_resp", exec_hist_resp)

    @markers.aws.validated
    def test_list_execution_no_such_state_machine(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)
        sm_name = f"statemachine_{short_uid()}"

        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        state_machine_arn: str = creation_resp_1["stateMachineArn"]

        sm_nonexistent_name = f"statemachine_{short_uid()}"
        sm_nonexistent_arn = state_machine_arn.replace(sm_name, sm_nonexistent_name)
        sfn_snapshot.add_transformer(RegexTransformer(sm_nonexistent_arn, "ssm_nonexistent_arn"))

        with pytest.raises(Exception) as exc:
            aws_client.stepfunctions.list_executions(stateMachineArn=sm_nonexistent_arn)
        sfn_snapshot.match(
            "exception", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..exception_value"])
    def test_list_execution_invalid_arn(self, sfn_snapshot, aws_client):
        with pytest.raises(Exception) as exc:
            aws_client.stepfunctions.list_executions(stateMachineArn="invalid_state_machine_arn")
        sfn_snapshot.match(
            "exception", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

    @markers.aws.validated
    def test_get_execution_history_reversed(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        state_machine_arn = creation_resp["stateMachineArn"]

        exec_resp = aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn)
        execution_arn = exec_resp["executionArn"]

        await_execution_terminated(aws_client.stepfunctions, execution_arn)

        exec_hist_resp = aws_client.stepfunctions.get_execution_history(executionArn=execution_arn)
        sfn_snapshot.match("get_execution_history_reverseOrder[False]", exec_hist_resp)

        exec_hist_rev_resp = aws_client.stepfunctions.get_execution_history(
            executionArn=execution_arn, reverseOrder=True
        )
        sfn_snapshot.match("get_execution_history_reverseOrder[True]", exec_hist_rev_resp)

    @markers.aws.validated
    def test_invalid_start_execution_arn(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        sfn_snapshot.match("creation_resp", creation_resp)
        state_machine_arn = creation_resp["stateMachineArn"]
        state_machine_arn_invalid = state_machine_arn.replace(
            sm_name, f"statemachine_invalid_{sm_name}"
        )

        aws_client.stepfunctions.delete_state_machine(stateMachineArn=state_machine_arn)

        with pytest.raises(Exception) as resource_not_found:
            aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn_invalid)
        sfn_snapshot.match("start_exec_of_deleted", resource_not_found.value.response)

    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message", "$..message"])
    @markers.aws.validated
    def test_invalid_start_execution_input(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        sfn_snapshot.match("creation_resp", creation_resp)
        state_machine_arn = creation_resp["stateMachineArn"]

        with pytest.raises(Exception) as err:
            aws_client.stepfunctions.start_execution(
                stateMachineArn=state_machine_arn, input="not some json"
            )
        sfn_snapshot.match("start_exec_str_inp", err.value.response)

        with pytest.raises(Exception) as err:
            aws_client.stepfunctions.start_execution(
                stateMachineArn=state_machine_arn, input="{'not': 'json'"
            )
        sfn_snapshot.match("start_exec_not_json_inp", err.value.response)

        with pytest.raises(Exception) as err:
            aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn, input="")
        sfn_snapshot.match("start_res_empty", err.value.response)

        start_res_num = aws_client.stepfunctions.start_execution(
            stateMachineArn=state_machine_arn, input="2"
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(start_res_num, 0))
        sfn_snapshot.match("start_res_num", start_res_num)

        start_res_str = aws_client.stepfunctions.start_execution(
            stateMachineArn=state_machine_arn, input='"some text"'
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(start_res_str, 1))
        sfn_snapshot.match("start_res_str", start_res_str)

        start_res_null = aws_client.stepfunctions.start_execution(
            stateMachineArn=state_machine_arn, input="null"
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(start_res_null, 2))
        sfn_snapshot.match("start_res_null", start_res_null)

    @markers.aws.validated
    def test_stop_execution(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_WAIT_1_MIN)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        sfn_snapshot.match("creation_resp", creation_resp)
        state_machine_arn = creation_resp["stateMachineArn"]

        exec_resp = aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn)
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        sfn_snapshot.match("exec_resp", exec_resp)
        execution_arn = exec_resp["executionArn"]

        def _check_stated_entered(events: HistoryEventList) -> bool:
            # Check the evaluation entered the wait state, called State_1.
            for event in events:
                event_details = event.get("stateEnteredEventDetails")
                if event_details:
                    return event_details.get("name") == "State_1"
            return False

        # Wait until the state machine enters the wait state.
        await_on_execution_events(
            stepfunctions_client=aws_client.stepfunctions,
            execution_arn=execution_arn,
            check_func=_check_stated_entered,
        )

        stop_res = aws_client.stepfunctions.stop_execution(executionArn=execution_arn)
        sfn_snapshot.match("stop_res", stop_res)

        await_execution_aborted(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )

        exec_hist_resp = aws_client.stepfunctions.get_execution_history(executionArn=execution_arn)
        sfn_snapshot.match("exec_hist_resp", exec_hist_resp)

    @markers.aws.validated
    def test_create_update_state_machine_base_definition(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition_t0 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str_t0 = json.dumps(definition_t0)
        sm_name = f"statemachine_{short_uid()}"

        creation_resp_t0 = create_state_machine(
            name=sm_name, definition=definition_str_t0, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_t0, 0))
        sfn_snapshot.match("creation_resp_t0", creation_resp_t0)
        state_machine_arn = creation_resp_t0["stateMachineArn"]

        describe_resp_t0 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_t0", describe_resp_t0)

        definition_t1 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_t1["States"]["State_1"]["Result"].update({"Arg1": "AfterUpdate1"})
        definition_str_t1 = json.dumps(definition_t1)

        update_state_machine_res = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_str_t1
        )
        sfn_snapshot.match("update_state_machine_res", update_state_machine_res)

        describe_resp_t1 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_t1", describe_resp_t1)

        definition_t2 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_t2["States"]["State_1"]["Result"].update({"Arg1": "AfterUpdate2"})
        definition_str_t2 = json.dumps(definition_t2)

        update_state_machine_res_t2 = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_str_t2
        )
        sfn_snapshot.match("update_state_machine_res_t2", update_state_machine_res_t2)

        describe_resp_t2 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_t2", describe_resp_t2)

    @markers.aws.validated
    def test_create_update_state_machine_base_role_arn(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn_t0 = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn_t0, "snf_role_arn_t0"))

        definition_t0 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str_t0 = json.dumps(definition_t0)
        sm_name = f"statemachine_{short_uid()}"

        creation_resp_t0 = create_state_machine(
            name=sm_name, definition=definition_str_t0, roleArn=snf_role_arn_t0
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_t0, 0))
        sfn_snapshot.match("creation_resp_t0", creation_resp_t0)
        state_machine_arn = creation_resp_t0["stateMachineArn"]

        describe_resp_t0 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_t0", describe_resp_t0)

        snf_role_arn_t1 = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn_t1, "snf_role_arn_t1"))

        update_state_machine_res_t1 = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, roleArn=snf_role_arn_t1
        )
        sfn_snapshot.match("update_state_machine_res_t1", update_state_machine_res_t1)

        describe_resp_t1 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_t1", describe_resp_t1)

        snf_role_arn_t2 = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn_t2, "snf_role_arn_t2"))

        update_state_machine_res_t2 = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, roleArn=snf_role_arn_t2
        )
        sfn_snapshot.match("update_state_machine_res_t2", update_state_machine_res_t2)

        describe_resp_t2 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_t2", describe_resp_t2)

    @markers.aws.validated
    def test_create_update_state_machine_base_definition_and_role(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition_t0 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str_t0 = json.dumps(definition_t0)
        sm_name = f"statemachine_{short_uid()}"

        creation_resp_t0 = create_state_machine(
            name=sm_name, definition=definition_str_t0, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_t0, 0))
        sfn_snapshot.match("creation_resp_t0", creation_resp_t0)
        state_machine_arn = creation_resp_t0["stateMachineArn"]

        describe_resp_t0 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_t0", describe_resp_t0)

        definition_t1 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_t1["States"]["State_1"]["Result"].update({"Arg1": "AfterUpdate1"})
        definition_str_t1 = json.dumps(definition_t1)

        snf_role_arn_t1 = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn_t1, "snf_role_arn_t1"))

        update_state_machine_res_t1 = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_str_t1, roleArn=snf_role_arn_t1
        )
        sfn_snapshot.match("update_state_machine_res_t1", update_state_machine_res_t1)

        describe_resp_t1 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_t1", describe_resp_t1)

        definition_t2 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_t2["States"]["State_1"]["Result"].update({"Arg1": "AfterUpdate2"})
        definition_str_t2 = json.dumps(definition_t2)

        snf_role_arn_t2 = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn_t2, "snf_role_arn_t2"))

        update_state_machine_res_t2 = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_str_t2, roleArn=snf_role_arn_t2
        )
        sfn_snapshot.match("update_state_machine_res_t2", update_state_machine_res_t2)

        describe_resp_t2 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_t2", describe_resp_t2)

    @markers.aws.validated
    def test_create_update_state_machine_base_update_none(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition_t0 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str_t0 = json.dumps(definition_t0)
        sm_name = f"statemachine_{short_uid()}"

        creation_resp_t0 = create_state_machine(
            name=sm_name, definition=definition_str_t0, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_t0, 0))
        sfn_snapshot.match("creation_resp_t0", creation_resp_t0)
        state_machine_arn = creation_resp_t0["stateMachineArn"]

        describe_resp_t0 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_t0", describe_resp_t0)

        with pytest.raises(Exception) as missing_required_parameter:
            aws_client.stepfunctions.update_state_machine(stateMachineArn=state_machine_arn)
        sfn_snapshot.match("missing_required_parameter", missing_required_parameter.value.response)

        with pytest.raises(Exception) as null_required_parameter:
            aws_client.stepfunctions.update_state_machine(
                stateMachineArn=state_machine_arn, definition=None, roleArn=None
            )
        sfn_snapshot.match("null_required_parameter", null_required_parameter.value)

    @markers.aws.validated
    def test_create_update_state_machine_same_parameters(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn_t0 = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn_t0, "snf_role_arn_t0"))

        definition_t0 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str_t0 = json.dumps(definition_t0)
        sm_name = f"statemachine_{short_uid()}"

        creation_resp_t0 = create_state_machine(
            name=sm_name, definition=definition_str_t0, roleArn=snf_role_arn_t0
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_t0, 0))
        sfn_snapshot.match("creation_resp_t0", creation_resp_t0)
        state_machine_arn = creation_resp_t0["stateMachineArn"]

        describe_resp_t0 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_t0", describe_resp_t0)

        snf_role_arn_t1 = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn_t1, "snf_role_arn_t1"))

        update_state_machine_res_t1 = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, roleArn=snf_role_arn_t1
        )
        sfn_snapshot.match("update_state_machine_res_t1", update_state_machine_res_t1)

        describe_resp_t1 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_t1", describe_resp_t1)

        update_state_machine_res_t2 = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_str_t0, roleArn=snf_role_arn_t1
        )
        sfn_snapshot.match("update_state_machine_res_t2", update_state_machine_res_t2)

        describe_resp_t2 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp_t2", describe_resp_t2)

    @markers.aws.validated
    def test_describe_state_machine_for_execution(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        sfn_snapshot.match("creation_resp", creation_resp)
        state_machine_arn = creation_resp["stateMachineArn"]

        exec_resp = aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn)
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        sfn_snapshot.match("exec_resp", exec_resp)
        execution_arn = exec_resp["executionArn"]

        await_execution_success(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )

        describe_resp = aws_client.stepfunctions.describe_state_machine_for_execution(
            executionArn=execution_arn
        )
        sfn_snapshot.match("describe_resp", describe_resp)

    @markers.aws.validated
    @pytest.mark.parametrize("encoder_function", [json.dumps, yaml.dump])
    def test_cloudformation_definition_create_describe(
        self,
        create_iam_role_for_sfn,
        sfn_snapshot,
        aws_client,
        encoder_function,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        state_machine_name = f"statemachine{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(state_machine_name, "state_machine_name"))
        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        stack_name = f"test-create-describe-yaml-{short_uid()}"
        cloudformation_template = {
            "Resources": {
                "MyStateMachine": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "StateMachineName": state_machine_name,
                        "Definition": definition,
                        "RoleArn": snf_role_arn,
                    },
                }
            }
        }
        cloudformation_template = encoder_function(cloudformation_template)

        aws_client.cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=cloudformation_template,
        )
        aws_client.cloudformation.get_waiter("stack_create_complete").wait(StackName=stack_name)

        list_state_machines_response = aws_client.stepfunctions.list_state_machines()
        state_machine = next(
            (
                sm
                for sm in list_state_machines_response["stateMachines"]
                if sm["name"] == state_machine_name
            ),
            None,
        )
        state_machine_arn = state_machine["stateMachineArn"]
        sfn_snapshot.add_transformer(RegexTransformer(state_machine_arn, "state_machine_arn"))

        describe_state_machine_response = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_state_machine_response", describe_state_machine_response)

        aws_client.cloudformation.delete_stack(StackName=stack_name)
        aws_client.cloudformation.get_waiter("stack_delete_complete").wait(StackName=stack_name)

        aws_client.stepfunctions.delete_state_machine(stateMachineArn=state_machine_arn)

    @markers.aws.validated
    @pytest.mark.parametrize("encoder_function", [json.dumps, yaml.dump])
    def test_cloudformation_definition_string_create_describe(
        self,
        create_iam_role_for_sfn,
        sfn_snapshot,
        aws_client,
        encoder_function,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        state_machine_name = f"statemachine{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(state_machine_name, "state_machine_name"))
        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_string = json.dumps(definition)
        stack_name = f"test-create-describe-yaml-{short_uid()}"
        cloudformation_template = {
            "Resources": {
                "MyStateMachine": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "StateMachineName": state_machine_name,
                        "DefinitionString": definition_string,
                        "RoleArn": snf_role_arn,
                    },
                }
            }
        }
        cloudformation_template = encoder_function(cloudformation_template)

        aws_client.cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=cloudformation_template,
        )
        aws_client.cloudformation.get_waiter("stack_create_complete").wait(StackName=stack_name)

        list_state_machines_response = aws_client.stepfunctions.list_state_machines()
        state_machine = next(
            (
                sm
                for sm in list_state_machines_response["stateMachines"]
                if sm["name"] == state_machine_name
            ),
            None,
        )
        state_machine_arn = state_machine["stateMachineArn"]
        sfn_snapshot.add_transformer(RegexTransformer(state_machine_arn, "state_machine_arn"))

        describe_state_machine_response = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_state_machine_response", describe_state_machine_response)

        aws_client.cloudformation.delete_stack(StackName=stack_name)
        aws_client.cloudformation.get_waiter("stack_delete_complete").wait(StackName=stack_name)

        aws_client.stepfunctions.delete_state_machine(stateMachineArn=state_machine_arn)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..redriveCount", "$..redriveStatus", "$..redriveStatusReason"]
    )
    def test_describe_execution(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        sfn_snapshot.match("creation_resp", creation_resp)
        state_machine_arn = creation_resp["stateMachineArn"]

        exec_resp = aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn)
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        sfn_snapshot.match("exec_resp", exec_resp)
        execution_arn = exec_resp["executionArn"]

        await_execution_success(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )

        describe_execution = aws_client.stepfunctions.describe_execution(executionArn=execution_arn)
        sfn_snapshot.match("ddescribe_execution", describe_execution)

    @markers.aws.validated
    def test_describe_execution_no_such_state_machine(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        state_machine_arn = creation_resp["stateMachineArn"]

        exec_resp = aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn)
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        execution_arn = exec_resp["executionArn"]

        await_execution_success(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )

        invalid_execution_arn = execution_arn[:-4] + "0000"
        sfn_snapshot.add_transformer(
            RegexTransformer(invalid_execution_arn, "invalid_execution_arn")
        )

        with pytest.raises(Exception) as exc:
            aws_client.stepfunctions.describe_execution(executionArn=invalid_execution_arn)
        sfn_snapshot.match(
            "exception", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..exception_value"])
    def test_describe_execution_invalid_arn(self, sfn_snapshot, aws_client):
        with pytest.raises(Exception) as exc:
            aws_client.stepfunctions.describe_execution(executionArn="invalid_state_machine_arn")
        sfn_snapshot.match(
            "exception", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..redriveCount", "$..redriveStatus", "$..redriveStatusReason"]
    )
    def test_describe_execution_arn_containing_punctuation(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"state.machine_{short_uid()}"
        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        sfn_snapshot.match("creation_resp", creation_resp)

        # ARN will contain a punctuation symbol
        exec_name: str = f"state.machine.execution_{short_uid()}"
        exec_resp = aws_client.stepfunctions.start_execution(
            stateMachineArn=creation_resp["stateMachineArn"], name=exec_name
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        sfn_snapshot.match("exec_resp", exec_resp)
        execution_arn = exec_resp["executionArn"]

        await_execution_success(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )

        describe_execution = aws_client.stepfunctions.describe_execution(executionArn=execution_arn)
        sfn_snapshot.match("describe_execution", describe_execution)

    @markers.aws.needs_fixing
    def test_get_execution_history_no_such_execution(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        state_machine_arn = creation_resp["stateMachineArn"]

        exec_resp = aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn)
        execution_arn = exec_resp["executionArn"]

        invalid_execution_arn = execution_arn[:-4] + "0000"
        sfn_snapshot.add_transformer(
            RegexTransformer(invalid_execution_arn, "invalid_execution_arn")
        )

        with pytest.raises(Exception) as exc:
            aws_client.stepfunctions.get_execution_history(executionArn=invalid_execution_arn)
        sfn_snapshot.match(
            "exception", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..exception_value"])
    def test_get_execution_history_invalid_arn(self, sfn_snapshot, aws_client):
        with pytest.raises(Exception) as exc:
            aws_client.stepfunctions.get_execution_history(executionArn="invalid_state_machine_arn")
        sfn_snapshot.match(
            "exception", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

    @markers.snapshot.skip_snapshot_verify(paths=["$..redriveCount"])
    @markers.aws.validated
    def test_state_machine_status_filter(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name = f"statemachine_{short_uid()}"
        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        sfn_snapshot.match("creation_resp", creation_resp)
        state_machine_arn = creation_resp["stateMachineArn"]

        list_response = aws_client.stepfunctions.list_executions(
            stateMachineArn=state_machine_arn, statusFilter="SUCCEEDED"
        )
        sfn_snapshot.match("list_before_execution", list_response)

        exec_resp = aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn)
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        sfn_snapshot.match("exec_resp", exec_resp)
        execution_arn = exec_resp["executionArn"]

        await_list_execution_status(
            stepfunctions_client=aws_client.stepfunctions,
            state_machine_arn=state_machine_arn,
            execution_arn=execution_arn,
            status="SUCCEEDED",
        )

        list_response = aws_client.stepfunctions.list_executions(
            stateMachineArn=state_machine_arn, statusFilter="SUCCEEDED"
        )
        sfn_snapshot.match("list_succeeded_when_complete", list_response)

        list_response = aws_client.stepfunctions.list_executions(
            stateMachineArn=state_machine_arn, statusFilter="RUNNING"
        )
        sfn_snapshot.match("list_running_when_complete", list_response)

        with pytest.raises(ClientError) as e:
            aws_client.stepfunctions.list_executions(
                stateMachineArn=state_machine_arn, statusFilter="succeeded"
            )
        sfn_snapshot.match("list_executions_filter_exc", e.value.response)
