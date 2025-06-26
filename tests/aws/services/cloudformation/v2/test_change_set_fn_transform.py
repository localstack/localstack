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
        name1 = f"name-1-{short_uid()}"
        name2 = f"name-2-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))

        bucket = s3_bucket
        file = tmp_path / "bucket_definition.yml"

        if include_format == "json":
            template = (
                '{"Parameter": { "Type": "AWS::SSM::Parameter","Properties": {"Name": "%s", "Type": "String", "Value": "foo"}}}'
                % name2
            )
        else:
            template = f"""
            Parameter2:
                Type: AWS::SSM::Parameter
                Properties:
                    Name: {name2}
                    Type: String
                    Value: foo
            """

        file.write_text(data=template)
        aws_client.s3.upload_file(
            Bucket=bucket,
            Key="template",
            Filename=str(file.absolute()),
        )

        template_1 = {
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": name1, "Type": "String", "Value": "foo"},
                },
            }
        }
        template_2 = {
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": name1, "Type": "String", "Value": "foo"},
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
        name1 = f"name-1-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))

        bucket = s3_bucket
        file = tmp_path / "bucket_definition.yml"

        if include_format == "json":
            template = '{"Outputs":{"ParameterRef":{"Value":{"Ref":"Parameter"}}}} '
        else:
            template = """
            Outputs:
                ParameterRef:
                    Value:
                        Ref: Parameter
            """

        file.write_text(data=template)
        aws_client.s3.upload_file(
            Bucket=bucket,
            Key="template",
            Filename=str(file.absolute()),
        )

        template_1 = {
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": name1, "Type": "String", "Value": "foo"},
                },
            }
        }
        template_2 = {
            "Transform": {
                "Name": "AWS::Include",
                "Parameters": {"Location": f"s3://{bucket}/template"},
            },
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": name1, "Type": "String", "Value": "foo"},
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Changes..ResourceChange.AfterContext.Properties.Body.paths",
            "$..Changes..ResourceChange.AfterContext.Properties.SourceArn",
        ]
    )
    def test_serverless_fn_transform(
        self, snapshot, capture_update_process, s3_bucket, aws_client, tmp_path
    ):
        name1 = f"name-1-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))

        template_1 = {
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Value": "{Substitution}", "Type": "String", "Name": name1},
                }
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
        name1 = f"name-1-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "name-1"))

        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../../../templates/macros/replace_string.py"
        )
        macro_name = "Substitution"
        create_macro(macro_name, macro_function_path)

        template_1 = {
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Value": "original", "Type": "String", "Name": name1},
                }
            }
        }

        template_2 = {
            "Parameters": {"Substitution": {"Type": "String", "Default": "SubstitutionDefault"}},
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Value": "{Substitution}", "Type": "String", "Name": name1},
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
        name1 = f"name-1-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "name-1"))

        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../../../templates/macros/add_standard_tags.py"
        )
        macro_name = "AddTags"
        create_macro(macro_name, macro_function_path)

        template_1 = {
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": name1, "Type": "String", "Value": "foo"},
                },
            }
        }

        template_2 = {
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": name1,
                        "Type": "String",
                        "Value": "foo",
                        "Fn::Transform": macro_name,
                    },
                }
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_embedded_macro_for_attribute_fn_transform(
        self,
        snapshot,
        capture_update_process,
        create_macro,
    ):
        name1 = f"parameter-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "parameter-name"))
        snapshot.add_transformer(snapshot.transform.key_value("Value", "value"))

        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../../../templates/macros/return_random_string.py"
        )
        macro_name = "GenerateRandom"
        create_macro(macro_name, macro_function_path)

        template_1 = {
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": name1, "Type": "String", "Value": "foo"},
                }
            }
        }

        template_2 = {
            "Parameters": {"Input": {"Type": "String"}},
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": name1,
                        "Type": "String",
                        "Value": {
                            "Fn::Transform": {
                                "Name": "GenerateRandom",
                                "Parameters": {"Prefix": {"Ref": "Input"}},
                            }
                        },
                    },
                }
            },
        }

        capture_update_process(snapshot, template_1, template_2, p2={"Input": "test"})

    @markers.aws.validated
    def test_multiple_fn_transform_order(
        self,
        snapshot,
        capture_update_process,
        create_macro,
    ):
        name1 = f"parameter-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "parameter-name"))
        snapshot.add_transformer(snapshot.transform.key_value("Value", "value"))

        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../../../templates/macros/replace_string.py"
        )
        macro_name = "ReplaceString"
        create_macro(macro_name, macro_function_path)

        template_1 = {
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": name1, "Type": "String", "Value": "foo"},
                }
            }
        }

        template_2 = {
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": name1,
                        "Value": "<replace-this>",
                        "Type": "String",
                        "Fn::Transform": [
                            {"Name": "ReplaceString", "Parameters": {"Input": "snippet-transform"}},
                            {
                                "Name": "ReplaceString",
                                "Parameters": {"Input": "second-snippet-transform"},
                            },
                        ],
                    },
                }
            },
            "Transform": [
                {"Name": "ReplaceString", "Parameters": {"Input": "global-transform"}},
                {"Name": "ReplaceString", "Parameters": {"Input": "second-global-transform"}},
            ],
        }

        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    @pytest.mark.parametrize("transform", ["true", "false"])
    def test_conditional_transform(
        self,
        transform,
        snapshot,
        capture_update_process,
        create_macro,
    ):
        name1 = f"parameter-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "parameter-name"))
        snapshot.add_transformer(snapshot.transform.key_value("Value", "value"))

        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../../../templates/macros/replace_string.py"
        )
        macro_name = "ReplaceString"
        create_macro(macro_name, macro_function_path)

        template_1 = {
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": name1, "Type": "String", "Value": "foo"},
                }
            }
        }

        template_2 = {
            "Parameters": {"Transform": {"Type": "String"}},
            "Conditions": {"Deploy": {"Fn::Equals": [{"Ref": "Transform"}, "true"]}},
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Condition": "Deploy",
                    "Properties": {
                        "Name": name1,
                        "Value": "<replace-this>",
                        "Type": "String",
                        "Fn::Transform": [
                            {"Name": "ReplaceString", "Parameters": {"Input": "snippet-transform"}},
                        ],
                    },
                }
            },
        }

        capture_update_process(snapshot, template_1, template_2, p2={"Transform": transform})

    @markers.aws.validated
    def test_macro_with_function(
        self,
        snapshot,
        capture_update_process,
        create_macro,
    ):
        name1 = f"parameter-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "parameter-name"))
        snapshot.add_transformer(snapshot.transform.key_value("Value", "value"))

        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../../../templates/macros/replace_string.py"
        )
        macro_name = "ReplaceString"
        create_macro(macro_name, macro_function_path)

        template_1 = {
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": name1, "Type": "String", "Value": "foo"},
                }
            }
        }

        template_2 = {
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": name1,
                        "Value": "<replace-this>",
                        "Type": "String",
                        "Fn::Transform": [
                            {
                                "Name": macro_name,
                                "Parameters": {"Input": {"Fn::Join": ["-", ["test", "string"]]}},
                            },
                        ],
                    },
                }
            }
        }

        capture_update_process(snapshot, template_1, template_2)
