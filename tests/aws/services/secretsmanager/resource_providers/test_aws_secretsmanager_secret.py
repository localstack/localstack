import os

from localstack.testing.pytest import markers


def deploy_stack(deploy_cfn_template, template_filename, **kwargs):
    template_path = os.path.join(os.path.dirname(__file__), "templates", template_filename)
    return deploy_cfn_template(template_path=template_path, **kwargs)


@markers.aws.validated
def test_update_secret_modify_properties(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "secret_all_properties.yml")
    secret_arn = stack.outputs["SecretArn"]

    secret = aws_client.secretsmanager.describe_secret(SecretId=secret_arn)
    snapshot.match("initial_description", {"Description": secret.get("Description")})
    snapshot.match("initial_tags", {"Tags": secret.get("Tags", [])})

    deploy_stack(
        deploy_cfn_template,
        "secret_all_properties_variant.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )

    secret = aws_client.secretsmanager.describe_secret(SecretId=secret_arn)
    snapshot.match("updated_description", {"Description": secret.get("Description")})
    snapshot.match("updated_tags", {"Tags": secret.get("Tags", [])})

    snapshot.add_transformer(snapshot.transform.regex(secret_arn, "<secret-arn>"))


@markers.aws.validated
def test_update_secret_remove_optional_properties(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "secret_all_properties.yml")
    secret_arn = stack.outputs["SecretArn"]

    deploy_stack(
        deploy_cfn_template,
        "secret_required_only.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )

    secret = aws_client.secretsmanager.describe_secret(SecretId=secret_arn)
    snapshot.match(
        "after_remove",
        {"Description": secret.get("Description", ""), "Tags": secret.get("Tags", [])},
    )

    snapshot.add_transformer(snapshot.transform.regex(secret_arn, "<secret-arn>"))
