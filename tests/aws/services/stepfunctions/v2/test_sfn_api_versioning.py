import json

import pytest

from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate
from tests.aws.services.stepfunctions.utils import (
    await_execution_lists_terminated,
    await_execution_terminated,
    await_state_machine_version_listed,
    await_state_machine_version_not_listed,
    is_old_provider,
)

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


@markers.snapshot.skip_snapshot_verify(paths=["$..loggingConfiguration", "$..tracingConfiguration"])
class TestSnfApiVersioning:
    @markers.aws.validated
    def test_create_with_publish(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        aws_client,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn, publish=True
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)

    @markers.aws.validated
    def test_create_with_version_description_no_publish(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        aws_client,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        with pytest.raises(Exception) as validation_exception:
            sm_name = f"statemachine_{short_uid()}"
            create_state_machine(
                name=sm_name,
                definition=definition_str,
                roleArn=snf_role_arn,
                versionDescription="HelloWorld!",
            )
        sfn_snapshot.match("validation_exception", validation_exception.value.response)

    @markers.aws.validated
    def test_create_publish_describe_no_version_description(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        aws_client,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn, publish=True
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)
        state_machine_arn = creation_resp_1["stateMachineArn"]
        state_machine_version_arn = creation_resp_1["stateMachineVersionArn"]

        describe_resp_version = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_version_arn
        )
        sfn_snapshot.match("describe_resp_version", describe_resp_version)

        describe_resp = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp", describe_resp)

    @markers.aws.validated
    def test_create_publish_describe_with_version_description(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        aws_client,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp_1 = create_state_machine(
            name=sm_name,
            definition=definition_str,
            roleArn=snf_role_arn,
            publish=True,
            versionDescription="HelloWorld!",
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)
        state_machine_arn = creation_resp_1["stateMachineArn"]
        state_machine_version_arn = creation_resp_1["stateMachineVersionArn"]

        describe_resp_version = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_version_arn
        )
        sfn_snapshot.match("describe_resp_version", describe_resp_version)

        describe_resp = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_resp", describe_resp)

    @markers.aws.validated
    def test_list_delete_version(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        aws_client,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn, publish=True
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)
        state_machine_arn = creation_resp_1["stateMachineArn"]
        state_machine_version_arn = creation_resp_1["stateMachineVersionArn"]

        describe_resp_version = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_version_arn
        )
        sfn_snapshot.match("describe_resp_version", describe_resp_version)

        await_state_machine_version_listed(
            aws_client.stepfunctions, state_machine_arn, state_machine_version_arn
        )

        list_versions_resp_1 = aws_client.stepfunctions.list_state_machine_versions(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("list_versions_resp_1", list_versions_resp_1)

        delete_version_resp = aws_client.stepfunctions.delete_state_machine_version(
            stateMachineVersionArn=state_machine_version_arn
        )
        sfn_snapshot.match("delete_version_resp", delete_version_resp)

        await_state_machine_version_not_listed(
            aws_client.stepfunctions, state_machine_arn, state_machine_version_arn
        )

        list_versions_resp_2 = aws_client.stepfunctions.list_state_machine_versions(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("list_versions_resp_2", list_versions_resp_2)

        delete_version_resp_after_del = aws_client.stepfunctions.delete_state_machine_version(
            stateMachineVersionArn=state_machine_version_arn
        )
        sfn_snapshot.match("delete_version_resp_after_del", delete_version_resp_after_del)

    @markers.aws.validated
    def test_update_state_machine(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        aws_client,
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
        state_machine_arn = creation_resp_1["stateMachineArn"]

        definition_r1 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_r1["Comment"] = f"{definition_r1['Comment']}-R1"
        definition_r1_str = json.dumps(definition_r1)

        update_resp_1 = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_r1_str, publish=True
        )
        sfn_snapshot.match("update_resp_1", update_resp_1)

        await_state_machine_version_listed(
            aws_client.stepfunctions, state_machine_arn, update_resp_1["stateMachineVersionArn"]
        )

        list_versions_resp_1 = aws_client.stepfunctions.list_state_machine_versions(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("list_versions_resp_1", list_versions_resp_1)

        definition_r2 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_r2["Comment"] = f"{definition_r2['Comment']}-R2"
        definition_r2_str = json.dumps(definition_r2)

        update_resp_2 = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_r2_str, publish=True
        )
        sfn_snapshot.match("update_resp_2", update_resp_2)
        state_machine_version_2_arn = update_resp_2["stateMachineVersionArn"]

        await_state_machine_version_listed(
            aws_client.stepfunctions, state_machine_arn, update_resp_2["stateMachineVersionArn"]
        )

        list_versions_resp_2 = aws_client.stepfunctions.list_state_machine_versions(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("list_versions_resp_2", list_versions_resp_2)

        definition_r3 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_r3["Comment"] = f"{definition_r3['Comment']}-R3"
        definition_r3_str = json.dumps(definition_r3)

        with pytest.raises(Exception) as invalid_arn_1:
            aws_client.stepfunctions.update_state_machine(
                stateMachineArn=state_machine_version_2_arn, definition=definition_r3_str
            )
        sfn_snapshot.match("invalid_arn_1", invalid_arn_1.value.response)

        with pytest.raises(Exception) as invalid_arn_2:
            aws_client.stepfunctions.update_state_machine(
                stateMachineArn=state_machine_version_2_arn,
                definition=definition_r3_str,
                publish=True,
            )
        sfn_snapshot.match("invalid_arn_2", invalid_arn_2.value.response)

    @markers.aws.validated
    def test_publish_state_machine_version(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        aws_client,
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
        state_machine_arn = creation_resp_1["stateMachineArn"]

        definition_r1 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_r1["Comment"] = f"{definition_r1['Comment']}-R1"
        definition_r1_str = json.dumps(definition_r1)

        update_resp_1 = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_r1_str
        )
        sfn_snapshot.match("update_resp_1", update_resp_1)

        publish_v1 = aws_client.stepfunctions.publish_state_machine_version(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("publish_v1", publish_v1)
        state_machine_v1_arn = publish_v1["stateMachineVersionArn"]

        await_state_machine_version_listed(
            aws_client.stepfunctions, state_machine_arn, state_machine_v1_arn
        )

        list_versions_resp_1 = aws_client.stepfunctions.list_state_machine_versions(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("list_versions_resp_1", list_versions_resp_1)

        describe_v1 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_v1_arn
        )
        sfn_snapshot.match("describe_v1", describe_v1)

        definition_r2 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_r2["Comment"] = f"{definition_r2['Comment']}-R2"
        definition_r2_str = json.dumps(definition_r2)

        update_resp_2 = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_r2_str
        )
        sfn_snapshot.match("update_resp_2", update_resp_2)
        revision_id_r2 = update_resp_2["revisionId"]

        publish_v2 = aws_client.stepfunctions.publish_state_machine_version(
            stateMachineArn=state_machine_arn, description="PublishedV2Description"
        )
        sfn_snapshot.match("publish_v2", publish_v2)
        state_machine_v2_arn = publish_v2["stateMachineVersionArn"]

        await_state_machine_version_listed(
            aws_client.stepfunctions, state_machine_arn, state_machine_v2_arn
        )

        list_versions_resp_2 = aws_client.stepfunctions.list_state_machine_versions(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("list_versions_resp_2", list_versions_resp_2)

        describe_v2 = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_v2_arn
        )
        sfn_snapshot.match("describe_v2", describe_v2)

        definition_r3 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_r3["Comment"] = f"{definition_r3['Comment']}-R3"
        definition_r3_str = json.dumps(definition_r3)

        update_resp_3 = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_r3_str
        )
        sfn_snapshot.match("update_resp_3", update_resp_3)

        with pytest.raises(Exception) as conflict_exception:
            aws_client.stepfunctions.publish_state_machine_version(
                stateMachineArn=state_machine_arn, revisionId=revision_id_r2
            )
        sfn_snapshot.match("conflict_exception", conflict_exception.value)

    @markers.aws.validated
    def test_start_version_execution(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        aws_client,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn, publish=True
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)
        state_machine_arn = creation_resp_1["stateMachineArn"]
        state_machine_version_arn = creation_resp_1["stateMachineVersionArn"]

        execution_resp = aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn)
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(execution_resp, 0))
        sfn_snapshot.match("execution_resp", execution_resp)
        execution_arn = execution_resp["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )

        await_execution_lists_terminated(
            stepfunctions_client=aws_client.stepfunctions,
            state_machine_arn=state_machine_arn,
            execution_arn=execution_arn,
        )

        exec_list_resp = aws_client.stepfunctions.list_executions(stateMachineArn=state_machine_arn)
        sfn_snapshot.match("exec_list_resp", exec_list_resp)

        execution_version_resp = aws_client.stepfunctions.start_execution(
            stateMachineArn=state_machine_version_arn
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_exec_arn(execution_version_resp, 1)
        )
        sfn_snapshot.match("execution_version_resp", execution_version_resp)
        version_execution_arn = execution_version_resp["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=version_execution_arn
        )

        await_execution_lists_terminated(
            stepfunctions_client=aws_client.stepfunctions,
            state_machine_arn=state_machine_version_arn,
            execution_arn=version_execution_arn,
        )

        exec_version_list_resp = aws_client.stepfunctions.list_executions(
            stateMachineArn=state_machine_version_arn
        )
        sfn_snapshot.match("exec_version_list_resp", exec_version_list_resp)

    @markers.aws.validated
    def test_version_ids_between_deletions(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        aws_client,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn, publish=True
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)
        state_machine_arn = creation_resp_1["stateMachineArn"]
        state_machine_arn_v1 = f"{state_machine_arn}:1"
        state_machine_arn_v2 = f"{state_machine_arn}:2"
        await_state_machine_version_listed(
            aws_client.stepfunctions, state_machine_arn, state_machine_arn_v1
        )

        definition_r2 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_r2["Comment"] = f"{definition_r2['Comment']}-R2"
        definition_r2_str = json.dumps(definition_r2)
        aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_r2_str, publish=True
        )
        await_state_machine_version_listed(
            aws_client.stepfunctions, state_machine_arn, state_machine_arn_v2
        )

        aws_client.stepfunctions.delete_state_machine_version(
            stateMachineVersionArn=state_machine_arn_v2
        )
        await_state_machine_version_not_listed(
            aws_client.stepfunctions, state_machine_arn, state_machine_arn_v2
        )

        publish_res_v2_2 = aws_client.stepfunctions.publish_state_machine_version(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("publish_res_v2_2", publish_res_v2_2)

    @markers.aws.validated
    def test_idempotent_publish(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        aws_client,
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
        state_machine_arn = creation_resp_1["stateMachineArn"]

        publish_v1_1 = aws_client.stepfunctions.publish_state_machine_version(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("publish_v1_1", publish_v1_1)
        await_state_machine_version_listed(
            aws_client.stepfunctions, state_machine_arn, f"{state_machine_arn}:1"
        )

        publish_v1_2 = aws_client.stepfunctions.publish_state_machine_version(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("publish_v1_2", publish_v1_2)

        list_versions_resp = aws_client.stepfunctions.list_state_machine_versions(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("list_versions_resp", list_versions_resp)

    @markers.aws.validated
    def test_empty_revision_with_publish_and_publish_on_creation(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        aws_client,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn, publish=True
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)
        state_machine_arn = creation_resp_1["stateMachineArn"]

        update_resp = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_str, publish=True
        )
        sfn_snapshot.match("update_resp_1", update_resp)

        update_resp_2 = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_str, publish=True
        )
        sfn_snapshot.match("update_resp_2", update_resp_2)

    @markers.aws.validated
    def test_empty_revision_with_publish_and_no_publish_on_creation(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        aws_client,
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
        state_machine_arn = creation_resp_1["stateMachineArn"]

        update_resp = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_str, publish=True
        )
        sfn_snapshot.match("update_resp_1", update_resp)

        update_resp_2 = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_str, publish=True
        )
        sfn_snapshot.match("update_resp_2", update_resp_2)

    @markers.aws.validated
    def test_describe_state_machine_for_execution_of_version(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        aws_client,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn, publish=True
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)
        state_machine_version_arn = creation_resp_1["stateMachineVersionArn"]

        execution_resp = aws_client.stepfunctions.start_execution(
            stateMachineArn=state_machine_version_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(execution_resp, 0))
        sfn_snapshot.match("execution_resp", execution_resp)
        execution_arn = execution_resp["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )

        describe_resp = aws_client.stepfunctions.describe_state_machine_for_execution(
            executionArn=execution_arn
        )
        sfn_snapshot.match("describe_resp", describe_resp)

    @markers.aws.validated
    def test_describe_state_machine_for_execution_of_version_with_revision(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        aws_client,
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
        state_machine_arn = creation_resp_1["stateMachineArn"]

        definition_r1 = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_r1["Comment"] = f"{definition_r1['Comment']}-R2"
        definition_r1_str = json.dumps(definition_r1)
        state_machine_arn_v1 = f"{state_machine_arn}:1"
        update_resp = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=definition_r1_str, publish=True
        )
        sfn_snapshot.match("update_resp", update_resp)
        await_state_machine_version_listed(
            aws_client.stepfunctions, state_machine_arn, state_machine_arn_v1
        )

        execution_resp = aws_client.stepfunctions.start_execution(
            stateMachineArn=state_machine_arn_v1
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(execution_resp, 0))
        sfn_snapshot.match("execution_resp", execution_resp)
        execution_arn = execution_resp["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )

        describe_resp = aws_client.stepfunctions.describe_state_machine_for_execution(
            executionArn=execution_arn
        )
        sfn_snapshot.match("describe_resp", describe_resp)
