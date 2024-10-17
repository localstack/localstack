import json
import os

import pytest
from botocore.exceptions import ClientError

from localstack.testing.aws.util import is_aws_cloud
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

    @markers.aws.validated
    def test_non_string_parameter_in_sub(self, deploy_cfn_template, aws_client, snapshot):
        ssm_parameter_name = f"test-param-{short_uid()}"
        snapshot.add_transformer(
            snapshot.transform.regex(ssm_parameter_name, "<ssm-parameter-name>")
        )
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../../templates/cfn_number_in_sub.yml"
            ),
            parameters={"ParameterName": ssm_parameter_name},
        )

        get_param_res = aws_client.ssm.get_parameter(Name=ssm_parameter_name)["Parameter"]
        snapshot.match("get-parameter-result", get_param_res)


@markers.aws.validated
def test_useful_error_when_invalid_ref(deploy_cfn_template, snapshot):
    """
    When trying to resolve a non-existent !Ref, make sure the error message includes the name of the !Ref
    to clarify which !Ref cannot be resolved.
    """
    logical_resource_id = "Topic"
    ref_name = "InvalidRef"

    template = json.dumps(
        {
            "Resources": {
                logical_resource_id: {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "Name": {
                            "Ref": ref_name,
                        },
                    },
                }
            }
        }
    )

    with pytest.raises(ClientError) as exc_info:
        deploy_cfn_template(template=template)

    snapshot.match("validation_error", exc_info.value.response)


@markers.aws.validated
def test_resolve_transitive_placeholders_in_strings(deploy_cfn_template, aws_client, snapshot):
    queue_name = f"q-{short_uid()}"
    parameter_ver = f"v{short_uid()}"
    stack_name = f"stack-{short_uid()}"
    stack = deploy_cfn_template(
        stack_name=stack_name,
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/legacy_transitive_ref.yaml"
        ),
        max_wait=300 if is_aws_cloud() else 10,
        parameters={"QueueName": queue_name, "Qualifier": parameter_ver},
    )
    tags = aws_client.sqs.list_queue_tags(QueueUrl=stack.outputs["QueueURL"])
    snapshot.add_transformer(
        snapshot.transform.regex(r"/cdk-bootstrap/(\w+)/", "/cdk-bootstrap/.../")
    )
    snapshot.match("tags", tags)
