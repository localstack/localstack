import os.path

from localstack.utils.strings import short_uid


def test_kms_key_disabled(sqs_client, kms_client, deploy_cfn_template):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/kms_key_disabled.yaml"
        )
    )

    key_id = stack.outputs["KeyIdOutput"]
    assert key_id
    my_key = kms_client.describe_key(KeyId=key_id)
    assert not my_key["KeyMetadata"]["Enabled"]


def test_cfn_with_kms_resources(deploy_cfn_template, kms_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../templates/template34.yaml")
    )

    alias_name = "alias/sample-5302"
    assert stack.outputs.get("KeyAlias") == alias_name

    def _get_matching_aliases():
        aliases = kms_client.list_aliases()["Aliases"]
        return [alias for alias in aliases if alias["AliasName"] == alias_name]

    assert len(_get_matching_aliases()) == 1

    stack.destroy()

    assert not _get_matching_aliases()


def test_deploy_stack_with_kms(kms_client, deploy_cfn_template, cfn_client):
    environment = f"env-{short_uid()}"

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/cdk_template_with_kms.json"
        ),
        parameters={"Environment": environment},
    )

    resources = cfn_client.list_stack_resources(StackName=stack.stack_name)[
        "StackResourceSummaries"
    ]
    kmskeys = [res for res in resources if res["ResourceType"] == "AWS::KMS::Key"]

    assert len(kmskeys) == 1
    assert kmskeys[0]["LogicalResourceId"] == "kmskeystack8A5DBE89"
    key_id = kmskeys[0]["PhysicalResourceId"]

    stack.destroy()

    resp = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
    assert resp["KeyState"] == "PendingDeletion"
