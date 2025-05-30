import os

import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.services.cloudformation.v2.utils import is_v2_engine
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@pytest.mark.skipif(
    condition=not is_v2_engine() and not is_aws_cloud(), reason="Requires the V2 engine"
)
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "per-resource-events..*",
        "delete-describe..*",
        #
        # Before/After Context
        "$..Capabilities",
        "$..NotificationARNs",
        "$..IncludeNestedStacks",
        "$..Scope",
        "$..Details",
        "$..Parameters",
        "$..Replacement",
        "$..PolicyAction",
    ]
)
class TestChangeSetFnTransform:
    @pytest.fixture(scope="function")
    def create_macro(self, aws_client, deploy_cfn_template, create_lambda_function):
        def _inner(macro_name, code_path):
            func_name = f"test_lambda_{short_uid()}"
            create_lambda_function(
                func_name=func_name,
                handler_file=code_path,
                runtime=Runtime.python3_12,
                client=aws_client.lambda_,
            )

            deploy_cfn_template(
                template_path=os.path.join(
                    os.path.dirname(__file__), "../../../templates/macro_resource.yml"
                ),
                parameters={"FunctionName": func_name, "MacroName": macro_name},
            )

        yield _inner

    @markers.aws.validated
    @pytest.mark.parametrize("include_format", ["yml", "json"])
    def test_embedded_fn_transform_include(
        self, include_format, snapshot, capture_update_process, s3_bucket, aws_client, tmp_path
    ):
        name1 = f"topic-name-1-{short_uid()}"
        name2 = f"topic-name-2-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))

        bucket = s3_bucket
        file = tmp_path / "bucket_definition.yml"

        if include_format == "json":
            template = (
                '{"Topic2":{"Type":"AWS::SNS::Topic","Properties":{"TopicName": "%s"}}}' % name2
            )
        else:
            template = f"""
            Topic2:
                Type: AWS::SNS::Topic
                Properties:
                    TopicName: {name2}
            """

        file.write_text(data=template)
        aws_client.s3.upload_file(
            Bucket=bucket,
            Key="template",
            Filename=str(file.absolute()),
        )

        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-1"},
                },
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::Sub": "The stack name is ${AWS::StackName}"},
                    },
                },
                "Fn::Transform": {
                    "Name": "AWS::Include",
                    "Parameters": {"Location": f"s3://{bucket}/template"},
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    @pytest.mark.parametrize("include_format", ["yml", "json"])
    def test_global_fn_transform_include(
        self, include_format, snapshot, capture_update_process, s3_bucket, aws_client, tmp_path
    ):
        name1 = f"topic-name-1-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))

        bucket = s3_bucket
        file = tmp_path / "bucket_definition.yml"

        if include_format == "json":
            template = '{"Outputs":{"TopicRef":{"Value":{"Ref":"Topic1"}}}} '
        else:
            template = """
            Outputs:
                TopicRef:
                    Value:
                        Ref: Topic1
            """

        file.write_text(data=template)
        aws_client.s3.upload_file(
            Bucket=bucket,
            Key="template",
            Filename=str(file.absolute()),
        )

        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-1"},
                },
            }
        }
        template_2 = {
            "Transform": {
                "Name": "AWS::Include",
                "Parameters": {"Location": f"s3://{bucket}/template"},
            },
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::Sub": "The stack name is ${AWS::StackName}"},
                    },
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_serverless_fn_transform(
        self, snapshot, capture_update_process, s3_bucket, aws_client, tmp_path
    ):
        name1 = f"topic-name-1-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))

        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-1"},
                },
            }
        }
        template_2 = {
            "Transform": "AWS::Serverless-2016-10-31",
            "Resources": {
                "HelloWorldFunction": {
                    "Type": "AWS::Serverless::Function",
                    "Properties": {
                        "Handler": "index.handler",
                        "Runtime": "nodejs18.x",
                        "InlineCode": "exports.handler = async (event) => {\n  return {\n    statusCode: 200,\n    body: JSON.stringify({ message: 'Hello from SAM inline function!' })\n  };\n};",
                        "Events": {
                            "ApiEvent": {
                                "Type": "Api",
                                "Properties": {"Path": "/hello", "Method": "get"},
                            }
                        },
                    },
                }
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_global_macro_fn_transform(
        self,
        snapshot,
        capture_update_process,
        create_macro,
    ):
        name1 = f"topic-name-1-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))

        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../../../templates/macros/replace_string.py"
        )
        macro_name = "Substitution"
        create_macro(macro_name, macro_function_path)

        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-1"},
                },
            }
        }

        template_2 = {
            "Parameters": {"Substitution": {"Type": "String", "Default": "SubstitutionDefault"}},
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Value": "{Substitution}", "Type": "String"},
                }
            },
            "Transform": {"Name": macro_name},
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_embedded_macro_fn_transform(
        self,
        snapshot,
        capture_update_process,
        create_macro,
    ):
        name1 = f"topic-name-1-{short_uid()}"
        name2 = f"topic-name-2-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))

        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../../../templates/macros/add_standard_attributes.py"
        )
        macro_name = "MakeFifo"
        create_macro(macro_name, macro_function_path)

        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1},
                },
            }
        }

        template_1 = {
            "Resources": {
                "Topic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name2, "Fn::Transform": macro_name},
                }
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    # TODO:
    # - Attribute with macro
    # - Macro with parameters
    # - Executing order of transformations
