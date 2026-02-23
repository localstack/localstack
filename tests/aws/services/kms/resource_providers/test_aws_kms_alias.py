import os

from localstack.testing.pytest import markers


def deploy_stack(deploy_cfn_template, template_filename, **kwargs):
    template_path = os.path.join(os.path.dirname(__file__), "templates", template_filename)
    return deploy_cfn_template(template_path=template_path, **kwargs)


@markers.aws.validated
def test_update_kms_alias_change_target_key(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "kms_alias_all_properties.yml")
    alias_name = stack.outputs["AliasName"]

    # Verify initial alias target
    aliases = aws_client.kms.list_aliases()["Aliases"]
    alias = [a for a in aliases if a["AliasName"] == alias_name][0]
    initial_target = alias["TargetKeyId"]
    snapshot.match("initial_target", {"TargetKeyId": initial_target})

    # Update to point to a different key
    deploy_stack(
        deploy_cfn_template,
        "kms_alias_all_properties_variant.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )

    aliases = aws_client.kms.list_aliases()["Aliases"]
    alias = [a for a in aliases if a["AliasName"] == alias_name][0]
    updated_target = alias["TargetKeyId"]
    snapshot.match("updated_target", {"TargetKeyId": updated_target})

    # Target should have changed
    assert initial_target != updated_target
