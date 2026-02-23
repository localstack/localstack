import os

from localstack.testing.pytest import markers


def deploy_stack(deploy_cfn_template, template_filename, **kwargs):
    template_path = os.path.join(os.path.dirname(__file__), "templates", template_filename)
    return deploy_cfn_template(template_path=template_path, **kwargs)


@markers.aws.validated
def test_update_kms_key_modify_properties(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "kms_key_all_properties.yml")
    key_id = stack.outputs["KeyId"]

    key_info = aws_client.kms.describe_key(KeyId=key_id)["KeyMetadata"]
    snapshot.match("initial_description", {"Description": key_info.get("Description")})
    snapshot.match("initial_enabled", {"Enabled": key_info.get("Enabled")})

    rotation = aws_client.kms.get_key_rotation_status(KeyId=key_id)
    snapshot.match("initial_rotation", {"KeyRotationEnabled": rotation["KeyRotationEnabled"]})

    tags = aws_client.kms.list_resource_tags(KeyId=key_id)
    snapshot.match("initial_tags", {"Tags": tags["Tags"]})

    deploy_stack(
        deploy_cfn_template,
        "kms_key_all_properties_variant.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )

    key_info = aws_client.kms.describe_key(KeyId=key_id)["KeyMetadata"]
    snapshot.match("updated_description", {"Description": key_info.get("Description")})
    snapshot.match("updated_enabled", {"Enabled": key_info.get("Enabled")})

    rotation = aws_client.kms.get_key_rotation_status(KeyId=key_id)
    snapshot.match("updated_rotation", {"KeyRotationEnabled": rotation["KeyRotationEnabled"]})

    tags = aws_client.kms.list_resource_tags(KeyId=key_id)
    snapshot.match("updated_tags", {"Tags": tags["Tags"]})


@markers.aws.validated
def test_update_kms_key_remove_optional_properties(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "kms_key_all_properties.yml")
    key_id = stack.outputs["KeyId"]

    deploy_stack(
        deploy_cfn_template,
        "kms_key_required_only.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )

    key_info = aws_client.kms.describe_key(KeyId=key_id)["KeyMetadata"]
    snapshot.match("after_remove_description", {"Description": key_info.get("Description")})

    tags = aws_client.kms.list_resource_tags(KeyId=key_id)
    snapshot.match("after_remove_tags", {"Tags": tags["Tags"]})
