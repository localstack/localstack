import os

import pytest

from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid


class TestDependsOn:
    @pytest.mark.skip(reason="not supported yet")
    @markers.aws.validated
    def test_depends_on_with_missing_reference(
        self, deploy_cfn_template, aws_client, cleanups, snapshot
    ):
        stack_name = f"test-stack-{short_uid()}"
        template_path = os.path.join(
            os.path.dirname(__file__),
            "../../../templates/engine/cfn_dependson_nonexisting_resource.yaml",
        )
        cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))

        with pytest.raises(aws_client.cloudformation.exceptions.ClientError) as e:
            aws_client.cloudformation.create_change_set(
                StackName=stack_name,
                ChangeSetName="init",
                ChangeSetType="CREATE",
                TemplateBody=load_file(template_path),
            )
        snapshot.match("depends_on_nonexisting_exception", e.value.response)


class TestFnSub:
    # TODO: add test for list sub without a second argument (i.e. the list)
    #   => Template error: One or more Fn::Sub intrinsic functions don't specify expected arguments. Specify a string as first argument, and an optional second argument to specify a mapping of values to replace in the string

    @markers.aws.validated
    def test_fn_sub_cases(self, deploy_cfn_template, aws_client, snapshot):
        ssm_parameter_name = f"test-param-{short_uid()}"
        snapshot.add_transformer(
            snapshot.transform.regex(ssm_parameter_name, "<ssm-parameter-name>")
        )
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "UrlSuffixPseudoParam", "<url-suffix>", reference_replacement=False
            )
        )
        deployment = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../../templates/engine/cfn_fn_sub.yaml"
            ),
            parameters={"ParameterName": ssm_parameter_name},
        )

        snapshot.match("outputs", deployment.outputs)
