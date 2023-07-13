import os.path


def test_simple_param_usage(aws_client, deploy_cfn_template):
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/engine/cfn_parameters.yaml"
        ),
        parameters={"MyParameterValue": "somevalue"},
    )
