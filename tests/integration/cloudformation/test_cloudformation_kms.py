import os.path


def test_kms_key_disabled(sqs_client, kms_client, deploy_cfn_template):
    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../templates/kms_key_disabled.yaml")
    )

    key_id = stack.outputs["KeyIdOutput"]
    assert key_id
    my_key = kms_client.describe_key(KeyId=key_id)
    assert not my_key["KeyMetadata"]["Enabled"]
