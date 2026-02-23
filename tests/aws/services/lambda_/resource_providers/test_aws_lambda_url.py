import os

from localstack.testing.pytest import markers


def deploy_stack(deploy_cfn_template, template_filename, **kwargs):
    template_path = os.path.join(os.path.dirname(__file__), "templates", template_filename)
    return deploy_cfn_template(template_path=template_path, **kwargs)


@markers.aws.validated
def test_update_lambda_url_modify_properties(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "lambda_url_all_properties.yml")
    function_name = stack.outputs["FunctionName"]

    url_config = aws_client.lambda_.get_function_url_config(FunctionName=function_name)
    snapshot.match("initial_auth_type", {"AuthType": url_config["AuthType"]})
    snapshot.match("initial_cors", {"Cors": url_config.get("Cors", {})})

    deploy_stack(
        deploy_cfn_template,
        "lambda_url_all_properties_variant.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )

    url_config = aws_client.lambda_.get_function_url_config(FunctionName=function_name)
    snapshot.match("updated_auth_type", {"AuthType": url_config["AuthType"]})
    snapshot.match("updated_cors", {"Cors": url_config.get("Cors", {})})

    snapshot.add_transformer(snapshot.transform.key_value("FunctionUrl", "<function-url>"))
