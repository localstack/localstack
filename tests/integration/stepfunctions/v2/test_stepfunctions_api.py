import json

import pytest

from localstack.aws.api.stepfunctions import StateMachineType
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON39
from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.utils.strings import short_uid
from tests.integration.stepfunctions.lambda_functions import lambda_functions
from tests.integration.stepfunctions.templates import templates
from tests.integration.stepfunctions.utils import (
    await_execution_aborted,
    await_execution_started,
    await_execution_success,
    await_no_state_machines_listed,
    await_state_machine_listed,
    await_state_machine_not_listed,
    is_old_provider,
)

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


@pytest.mark.skip_snapshot_verify(
    paths=["$..loggingConfiguration", "$..tracingConfiguration", "$..previousEventId"]
)
class TestSnfApi:
    def test_create_delete_valid_sm(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_lambda_function,
        create_state_machine,
        snapshot,
    ):
        create_lambda_1 = create_lambda_function(
            handler_file=lambda_functions.BASE_ID_FUNCTION,
            func_name="id_function",
            runtime=LAMBDA_RUNTIME_PYTHON39,
        )
        lambda_arn_1 = create_lambda_1["CreateFunctionResponse"]["FunctionArn"]

        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = templates.load_sfn_template(templates.BASE_TASK_SEQ_2)
        definition["States"]["State_1"]["Resource"] = lambda_arn_1
        definition["States"]["State_2"]["Resource"] = lambda_arn_1
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        snapshot.match("creation_resp_1", creation_resp_1)

        state_machine_arn = creation_resp_1["stateMachineArn"]

        deletion_resp_1 = stepfunctions_client.delete_state_machine(
            stateMachineArn=state_machine_arn
        )
        snapshot.match("deletion_resp_1", deletion_resp_1)

    @pytest.mark.skip("Add support for invalid language derivation.")
    def test_create_delete_invalid_sm(
        self, stepfunctions_client, create_iam_role_for_sfn, create_state_machine, snapshot
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = templates.load_sfn_template(templates.BASE_INVALID_DER)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"

        with pytest.raises(Exception) as resource_not_found:
            create_state_machine(name=sm_name, definition=definition_str, roleArn=snf_role_arn)
        snapshot.match("invalid_definition_1", resource_not_found.value.response)

    def test_delete_nonexistent_sm(
        self, stepfunctions_client, create_iam_role_for_sfn, create_state_machine, snapshot
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = templates.load_sfn_template(templates.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)
        sm_name = f"statemachine_{short_uid()}"

        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        state_machine_arn: str = creation_resp_1["stateMachineArn"]

        sm_nonexistent_name = f"statemachine_{short_uid()}"
        sm_nonexistent_arn = state_machine_arn.replace(sm_name, sm_nonexistent_name)

        deletion_resp_1 = stepfunctions_client.delete_state_machine(
            stateMachineArn=sm_nonexistent_arn
        )
        snapshot.match("deletion_resp_1", deletion_resp_1)

    def test_create_exact_duplicate_sm(
        self, stepfunctions_client, create_iam_role_for_sfn, create_state_machine, snapshot
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = templates.load_sfn_template(templates.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)
        sm_name = f"statemachine_{short_uid()}"

        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        snapshot.match("creation_resp_1", creation_resp_1)
        state_machine_arn_1 = creation_resp_1["stateMachineArn"]

        describe_resp_1 = stepfunctions_client.describe_state_machine(
            stateMachineArn=state_machine_arn_1
        )
        snapshot.match("describe_resp_1", describe_resp_1)

        creation_resp_2 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp_2, 1))
        snapshot.match("creation_resp_2", creation_resp_2)
        state_machine_arn_2 = creation_resp_2["stateMachineArn"]

        describe_resp_2 = stepfunctions_client.describe_state_machine(
            stateMachineArn=state_machine_arn_2
        )
        snapshot.match("describe_resp_2", describe_resp_2)

        describe_resp_1_2 = stepfunctions_client.describe_state_machine(
            stateMachineArn=state_machine_arn_1
        )
        snapshot.match("describe_resp_1_2", describe_resp_1_2)

    def test_create_duplicate_definition_format_sm(
        self, stepfunctions_client, create_iam_role_for_sfn, create_state_machine, snapshot
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = templates.load_sfn_template(templates.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)
        sm_name = f"statemachine_{short_uid()}"

        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        snapshot.match("creation_resp_1", creation_resp_1)
        state_machine_arn_1 = creation_resp_1["stateMachineArn"]

        describe_resp_1 = stepfunctions_client.describe_state_machine(
            stateMachineArn=state_machine_arn_1
        )
        snapshot.match("describe_resp_1", describe_resp_1)

        definition_str_2 = json.dumps(definition, indent=4)
        with pytest.raises(Exception) as resource_not_found:
            create_state_machine(name=sm_name, definition=definition_str_2, roleArn=snf_role_arn)
        snapshot.match("already_exists_1", resource_not_found.value.response)

    def test_create_duplicate_sm_name(
        self, stepfunctions_client, create_iam_role_for_sfn, create_state_machine, snapshot
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition_1 = templates.load_sfn_template(templates.BASE_PASS_RESULT)
        definition_str_1 = json.dumps(definition_1)
        sm_name = f"statemachine_{short_uid()}"

        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str_1, roleArn=snf_role_arn
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        snapshot.match("creation_resp_1", creation_resp_1)
        state_machine_arn_1 = creation_resp_1["stateMachineArn"]

        describe_resp_1 = stepfunctions_client.describe_state_machine(
            stateMachineArn=state_machine_arn_1
        )
        snapshot.match("describe_resp_1", describe_resp_1)

        definition_2 = templates.load_sfn_template(templates.BASE_PASS_RESULT)
        definition_2["States"]["State_1"]["Result"].update({"Arg2": "Argument2"})
        definition_str_2 = json.dumps(definition_2)

        with pytest.raises(Exception) as resource_not_found:
            create_state_machine(name=sm_name, definition=definition_str_2, roleArn=snf_role_arn)
        snapshot.match("already_exists_1", resource_not_found.value.response)

    def test_list_sms(
        self, stepfunctions_client, create_iam_role_for_sfn, create_state_machine, snapshot
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = templates.load_sfn_template(templates.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        await_no_state_machines_listed(stepfunctions_client=stepfunctions_client)

        lst_resp = stepfunctions_client.list_state_machines()
        snapshot.match("lst_resp_init", lst_resp)

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
                type=StateMachineType.EXPRESS,
            )
            snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp, i))
            snapshot.match(f"creation_resp_{i}", creation_resp)
            state_machine_arn: str = creation_resp["stateMachineArn"]
            state_machine_arns.append(state_machine_arn)

            await_state_machine_listed(
                stepfunctions_client=stepfunctions_client, state_machine_arn=state_machine_arn
            )
            lst_resp = stepfunctions_client.list_state_machines()
            snapshot.match(f"lst_resp_{i}", lst_resp)

        for i, state_machine_arn in enumerate(state_machine_arns):
            deletion_resp = stepfunctions_client.delete_state_machine(
                stateMachineArn=state_machine_arn
            )
            snapshot.match(f"deletion_resp_{i}", deletion_resp)

            await_state_machine_not_listed(
                stepfunctions_client=stepfunctions_client, state_machine_arn=state_machine_arn
            )

            lst_resp = stepfunctions_client.list_state_machines()
            snapshot.match(f"lst_resp_del_{i}", lst_resp)

        lst_resp = stepfunctions_client.list_state_machines()
        snapshot.match("lst_resp_del_end", lst_resp)

    @pytest.mark.skip_snapshot_verify(paths=["$..executions..status"])
    def test_start_execution(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = templates.load_sfn_template(templates.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        snapshot.match("creation_resp", creation_resp)
        state_machine_arn = creation_resp["stateMachineArn"]

        exec_resp = stepfunctions_client.start_execution(stateMachineArn=state_machine_arn)
        snapshot.add_transformer(snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        snapshot.match("exec_resp", exec_resp)
        execution_arn = exec_resp["executionArn"]

        await_execution_success(
            stepfunctions_client=stepfunctions_client, execution_arn=execution_arn
        )

        exec_list_resp = stepfunctions_client.list_executions(stateMachineArn=state_machine_arn)
        snapshot.match("exec_list_resp", exec_list_resp)

        exec_hist_resp = stepfunctions_client.get_execution_history(executionArn=execution_arn)
        snapshot.match("exec_hist_resp", exec_hist_resp)

    def test_invalid_start_execution_arn(
        self, stepfunctions_client, create_iam_role_for_sfn, create_state_machine, snapshot
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = templates.load_sfn_template(templates.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        snapshot.match("creation_resp", creation_resp)
        state_machine_arn = creation_resp["stateMachineArn"]
        state_machine_arn_invalid = state_machine_arn.replace(
            sm_name, f"statemachine_invalid_{sm_name}"
        )

        stepfunctions_client.delete_state_machine(stateMachineArn=state_machine_arn)

        with pytest.raises(Exception) as resource_not_found:
            stepfunctions_client.start_execution(stateMachineArn=state_machine_arn_invalid)
        snapshot.match("start_exec_of_deleted", resource_not_found.value.response)

    @pytest.mark.skip_snapshot_verify(paths=["$..Error.Message", "$..message"])
    def test_invalid_start_execution_input(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = templates.load_sfn_template(templates.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        snapshot.match("creation_resp", creation_resp)
        state_machine_arn = creation_resp["stateMachineArn"]

        with pytest.raises(Exception) as err:
            stepfunctions_client.start_execution(
                stateMachineArn=state_machine_arn, input="not some json"
            )
        snapshot.match("start_exec_str_inp", err.value.response)

        with pytest.raises(Exception) as err:
            stepfunctions_client.start_execution(
                stateMachineArn=state_machine_arn, input="{'not': 'json'"
            )
        snapshot.match("start_exec_not_json_inp", err.value.response)

        with pytest.raises(Exception) as err:
            stepfunctions_client.start_execution(stateMachineArn=state_machine_arn, input="")
        snapshot.match("start_res_empty", err.value.response)

        start_res_num = stepfunctions_client.start_execution(
            stateMachineArn=state_machine_arn, input="2"
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_exec_arn(start_res_num, 0))
        snapshot.match("start_res_num", start_res_num)

        start_res_str = stepfunctions_client.start_execution(
            stateMachineArn=state_machine_arn, input='"some text"'
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_exec_arn(start_res_str, 1))
        snapshot.match("start_res_str", start_res_str)

        start_res_null = stepfunctions_client.start_execution(
            stateMachineArn=state_machine_arn, input="null"
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_exec_arn(start_res_null, 2))
        snapshot.match("start_res_null", start_res_null)

    def test_stop_execution(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = templates.load_sfn_template(templates.BASE_WAIT_1_MIN)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        snapshot.match("creation_resp", creation_resp)
        state_machine_arn = creation_resp["stateMachineArn"]

        exec_resp = stepfunctions_client.start_execution(stateMachineArn=state_machine_arn)
        snapshot.add_transformer(snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        snapshot.match("exec_resp", exec_resp)
        execution_arn = exec_resp["executionArn"]

        await_execution_started(
            stepfunctions_client=stepfunctions_client, execution_arn=execution_arn
        )

        stop_res = stepfunctions_client.stop_execution(executionArn=execution_arn)
        snapshot.match("stop_res", stop_res)

        await_execution_aborted(
            stepfunctions_client=stepfunctions_client, execution_arn=execution_arn
        )

        exec_hist_resp = stepfunctions_client.get_execution_history(executionArn=execution_arn)
        snapshot.match("exec_hist_resp", exec_hist_resp)
