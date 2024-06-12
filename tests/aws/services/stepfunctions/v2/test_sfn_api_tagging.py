import json

import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.stepfunctions import Tag
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate


@markers.snapshot.skip_snapshot_verify(paths=["$..tracingConfiguration"])
class TestSnfApiTagging:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "tag_list",
        [
            [],
            [Tag(key="key1", value="value1")],
            [Tag(key="key1", value="")],
            [Tag(key="key1", value="value1"), Tag(key="key1", value="value1")],
            [Tag(key="key1", value="value1"), Tag(key="key2", value="value2")],
        ],
    )
    def test_tag_state_machine(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client, tag_list
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        state_machine_arn = creation_resp_1["stateMachineArn"]
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)

        tag_resource_resp = aws_client.stepfunctions.tag_resource(
            resourceArn=state_machine_arn, tags=tag_list
        )
        sfn_snapshot.match("tag_resource_resp", tag_resource_resp)

        list_resources_res = aws_client.stepfunctions.list_tags_for_resource(
            resourceArn=state_machine_arn
        )
        sfn_snapshot.match("list_resources_res", list_resources_res)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "tag_list",
        [
            None,
            [Tag(key="", value="value")],
            [Tag(key=None, value="value")],
            [Tag(key="key1", value=None)],
        ],
    )
    def test_tag_invalid_state_machine(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client, tag_list
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        state_machine_arn = creation_resp_1["stateMachineArn"]
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)

        with pytest.raises(Exception) as error:
            aws_client.stepfunctions.tag_resource(resourceArn=state_machine_arn, tags=tag_list)
        sfn_snapshot.match("error", error.value)

    @markers.aws.validated
    def test_tag_state_machine_version(
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
        state_machine_arn = creation_resp_1["stateMachineArn"]
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)

        publish_resp = aws_client.stepfunctions.publish_state_machine_version(
            stateMachineArn=state_machine_arn
        )
        state_machine_version_arn = publish_resp["stateMachineVersionArn"]
        sfn_snapshot.match("publish_resp", publish_resp)

        with pytest.raises(Exception) as error:
            aws_client.stepfunctions.tag_resource(
                resourceArn=state_machine_version_arn, tags=[Tag(key="key1", value="value1")]
            )
        sfn_snapshot.match("error", error.value)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "tag_keys",
        [
            [],
            ["key1"],
            ["key1", "key1"],
            ["key1", "key2"],
        ],
    )
    def test_untag_state_machine(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client, tag_keys
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"
        creation_resp_1 = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        state_machine_arn = creation_resp_1["stateMachineArn"]
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)

        tag_resource_resp = aws_client.stepfunctions.tag_resource(
            resourceArn=state_machine_arn, tags=[Tag(key="key1", value="value1")]
        )
        sfn_snapshot.match("tag_resource_resp", tag_resource_resp)

        untag_resource_resp = aws_client.stepfunctions.untag_resource(
            resourceArn=state_machine_arn, tagKeys=tag_keys
        )
        sfn_snapshot.match("untag_resource_resp", untag_resource_resp)

        list_resources_res = aws_client.stepfunctions.list_tags_for_resource(
            resourceArn=state_machine_arn
        )
        sfn_snapshot.match("list_resources_res", list_resources_res)

    @markers.aws.validated
    def test_create_state_machine(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
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
            tags=[Tag(key="key1", value="value1"), Tag(key="key2", value="value2")],
        )
        state_machine_arn = creation_resp_1["stateMachineArn"]
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp_1, 0))
        sfn_snapshot.match("creation_resp_1", creation_resp_1)

        list_resources_res = aws_client.stepfunctions.list_tags_for_resource(
            resourceArn=state_machine_arn
        )
        sfn_snapshot.match("list_resources_res", list_resources_res)
