import os.path

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


@markers.aws.validated
def test_kms_key_disabled(deploy_cfn_template, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/kms_key_disabled.yaml"
        )
    )

    key_id = stack.outputs["KeyIdOutput"]
    assert key_id
    my_key = aws_client.kms.describe_key(KeyId=key_id)
    assert not my_key["KeyMetadata"]["Enabled"]


@markers.aws.validated
def test_cfn_with_kms_resources(deploy_cfn_template, aws_client, snapshot):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.key_value("KeyAlias"))

    alias_name = f"alias/sample-{short_uid()}"

    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../../templates/template34.yaml"),
        parameters={"AliasName": alias_name},
        max_wait=300,
    )
    snapshot.match("stack-outputs", stack.outputs)

    assert stack.outputs.get("KeyAlias") == alias_name

    def _get_matching_aliases():
        aliases = aws_client.kms.list_aliases()["Aliases"]
        return [alias for alias in aliases if alias["AliasName"] == alias_name]

    assert len(_get_matching_aliases()) == 1

    stack.destroy()

    assert not _get_matching_aliases()


@markers.aws.validated
def test_deploy_stack_with_kms(deploy_cfn_template, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../../templates/cfn_kms_key.yml"),
    )

    key_id = stack.outputs["KeyId"]

    stack.destroy()

    def assert_key_deleted():
        resp = aws_client.kms.describe_key(KeyId=key_id)["KeyMetadata"]
        assert resp["KeyState"] == "PendingDeletion"

    retry(assert_key_deleted, retries=5, sleep=5)
