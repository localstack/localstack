import base64
import json
import os

import botocore.exceptions
import pytest
import yaml

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.cloudformation_utils import load_template_raw
from localstack.utils.aws import arns
from localstack.utils.common import short_uid
from localstack.utils.files import load_file
from localstack.utils.sync import wait_until

TMPL = """
Resources:
  blaBE223B94:
    Type: AWS::SNS::Topic
  queue276F7297:
    Type: AWS::SQS::Queue
    Properties:
      DelaySeconds: "2"
      FifoQueue: "true"
    UpdateReplacePolicy: Delete
    DeletionPolicy: Delete
Outputs:
  QueueName:
    Value:
      Fn::GetAtt:
        - queue276F7297
        - QueueName
  QueueUrl:
    Value:
      Ref: queue276F7297
"""

TEST_TEMPLATE_26_1 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  MyQueue:
    Type: 'AWS::SQS::Queue'
    Properties:
      QueueName: %s
Outputs:
  TestOutput26:
    Value: !GetAtt MyQueue.Arn
    Export:
      Name: TestQueueArn26
"""

TEST_TEMPLATE_26_2 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  MessageQueue:
    Type: 'AWS::SQS::Queue'
    Properties:
      QueueName: %s
      RedrivePolicy:
        deadLetterTargetArn: !ImportValue TestQueueArn26
        maxReceiveCount: 3
Outputs:
  MessageQueueUrl1:
    Value: !ImportValue TestQueueArn26
  MessageQueueUrl2:
    Value: !Ref MessageQueue
"""


class TestTypes:
    @pytest.mark.aws_validated
    def test_implicit_type_conversion(self, deploy_cfn_template, cfn_client, sqs_client, snapshot):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        stack = deploy_cfn_template(template=TMPL, max_wait=180)
        queue = sqs_client.get_queue_attributes(
            QueueUrl=stack.outputs["QueueUrl"], AttributeNames=["All"]
        )
        snapshot.match("queue", queue)


class TestIntrinsicFunctions:
    @pytest.mark.parametrize(
        ("intrinsic_fn", "parameter_1", "parameter_2", "expected_bucket_created"),
        [
            ("Fn::And", "0", "0", False),
            ("Fn::And", "0", "1", False),
            ("Fn::And", "1", "0", False),
            ("Fn::And", "1", "1", True),
            ("Fn::Or", "0", "0", False),
            ("Fn::Or", "0", "1", True),
            ("Fn::Or", "1", "0", True),
            ("Fn::Or", "1", "1", True),
        ],
    )
    def test_and_or_functions(
        self,
        cfn_client,
        s3_client,
        intrinsic_fn,
        parameter_1,
        parameter_2,
        expected_bucket_created,
        deploy_cfn_template,
    ):
        bucket_name = f"ls-bucket-{short_uid()}"

        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../templates/cfn_intrinsic_functions.yaml"
            ),
            parameters={
                "Param1": parameter_1,
                "Param2": parameter_2,
                "BucketName": bucket_name,
            },
            template_mapping={
                "intrinsic_fn": intrinsic_fn,
            },
        )

        buckets = s3_client.list_buckets()
        bucket_names = [b["Name"] for b in buckets["Buckets"]]
        assert (bucket_name in bucket_names) == expected_bucket_created

    @pytest.mark.aws_validated
    def test_base64_sub_and_getatt_functions(self, deploy_cfn_template):
        template_path = os.path.join(
            os.path.dirname(__file__), "../templates/functions_getatt_sub_base64.yml"
        )
        original_string = f"string-{short_uid()}"
        deployed = deploy_cfn_template(
            template_path=template_path, parameters={"OriginalString": original_string}
        )

        converted_string = base64.b64encode(bytes(original_string, "utf-8")).decode("utf-8")
        assert converted_string == deployed.outputs["Encoded"]

    @pytest.mark.aws_validated
    def test_split_length_and_join_functions(self, deploy_cfn_template):
        template_path = os.path.join(
            os.path.dirname(__file__), "../templates/functions_select_split_join.yml"
        )

        first_value = f"string-{short_uid()}"
        second_value = f"string-{short_uid()}"
        deployed = deploy_cfn_template(
            template_path=template_path,
            parameters={
                "MultipleValues": f"{first_value};{second_value}",
                "Value1": first_value,
                "Value2": second_value,
            },
        )

        assert first_value == deployed.outputs["SplitResult"]
        assert f"{first_value}_{second_value}" == deployed.outputs["JoinResult"]

        # TODO support join+split and length operations
        # assert f"{first_value}_{second_value}" == deployed.outputs["SplitJoin"]
        # assert 2 == deployed.outputs["LengthResult"]

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="functions not currently supported")
    def test_json_and_find_in_map_functions(self, deploy_cfn_template):
        template_path = os.path.join(
            os.path.dirname(__file__), "../templates/function_to_json_string.yml"
        )

        first_value = f"string-{short_uid()}"
        second_value = f"string-{short_uid()}"
        deployed = deploy_cfn_template(
            template_path=template_path,
            parameters={
                "Value1": first_value,
                "Value2": second_value,
            },
        )

        json_result = json.loads(deployed.outputs["Result"])

        assert json_result["key1"] == first_value
        assert json_result["key2"] == second_value
        assert "value1" == deployed.outputs["Result2"]

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="function not currently supported")
    def test_cidr_function(self, deploy_cfn_template):
        template_path = os.path.join(os.path.dirname(__file__), "../templates/functions_cidr.yml")

        # TODO parametrize parameters and result
        deployed = deploy_cfn_template(
            template_path=template_path,
            parameters={"IpBlock": "10.0.0.0/16", "Count": "1", "CidrBits": "8", "Select": "0"},
        )

        assert deployed.outputs["Address"] == "10.0.0.0/24"

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="function not currently supported")
    def test_get_azs_function(self, deploy_cfn_template):
        template_path = os.path.join(
            os.path.dirname(__file__), "../templates/functions_get_azs.yml"
        )
        region = "us-east-1"  # TODO parametrize

        deployed = deploy_cfn_template(
            template_path=template_path,
            parameters={"Region": region},
        )

        zone = "us-east-1a"  # TODO parametrize
        assert zone in deployed.outputs["Zones"]


class TestImports:
    @pytest.mark.skip(reason="flaky due to issues in parameter handling and re-resolving")
    def test_stack_imports(self, deploy_cfn_template, cfn_client, sqs_client):
        result = cfn_client.list_imports(ExportName="_unknown_")
        assert result["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert result["Imports"] == []  # TODO: create test with actual import values!

        queue_name1 = f"q-{short_uid()}"
        queue_name2 = f"q-{short_uid()}"
        template1 = TEST_TEMPLATE_26_1 % queue_name1
        template2 = TEST_TEMPLATE_26_2 % queue_name2
        deploy_cfn_template(template=template1)
        stack2 = deploy_cfn_template(template=template2)

        queue_url1 = sqs_client.get_queue_url(QueueName=queue_name1)["QueueUrl"]
        queue_url2 = sqs_client.get_queue_url(QueueName=queue_name2)["QueueUrl"]

        queues = sqs_client.list_queues().get("QueueUrls", [])
        assert queue_url1 in queues
        assert queue_url2 in queues

        outputs = cfn_client.describe_stacks(StackName=stack2.stack_name)["Stacks"][0]["Outputs"]
        output = [out["OutputValue"] for out in outputs if out["OutputKey"] == "MessageQueueUrl1"][
            0
        ]
        assert arns.sqs_queue_arn(queue_url1) == output  # TODO
        output = [out["OutputValue"] for out in outputs if out["OutputKey"] == "MessageQueueUrl2"][
            0
        ]
        assert output == queue_url2


class TestSsmParameters:
    def test_create_stack_with_ssm_parameters(
        self, cfn_client, ssm_client, sns_client, deploy_cfn_template
    ):
        parameter_name = f"ls-param-{short_uid()}"
        parameter_value = f"ls-param-value-{short_uid()}"
        parameter_logical_id = "parameter123"
        ssm_client.put_parameter(Name=parameter_name, Value=parameter_value, Type="String")
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../templates/dynamicparameter_ssm_string.yaml"
            ),
            template_mapping={"parameter_name": parameter_name},
        )

        stack_description = cfn_client.describe_stacks(StackName=stack.stack_name)["Stacks"][0]
        assert stack_description is not None
        assert stack_description["Parameters"][0]["ParameterKey"] == parameter_logical_id
        assert stack_description["Parameters"][0]["ParameterValue"] == parameter_name
        assert stack_description["Parameters"][0]["ResolvedValue"] == parameter_value

        topics = sns_client.list_topics()
        topic_arns = [t["TopicArn"] for t in topics["Topics"]]
        assert any(parameter_value in t for t in topic_arns)

    def test_resolve_ssm(
        self,
        create_parameter,
        deploy_cfn_template,
    ):
        parameter_key = f"param-key-{short_uid()}"
        parameter_value = f"param-value-{short_uid()}"
        create_parameter(Name=parameter_key, Value=parameter_value, Type="String")

        result = deploy_cfn_template(
            parameters={"DynamicParameter": parameter_key},
            template_path=os.path.join(os.path.dirname(__file__), "../templates/resolve_ssm.yaml"),
        )

        topic_name = result.outputs["TopicName"]
        assert topic_name == parameter_value

    def test_resolve_ssm_with_version(
        self, ssm_client, cfn_client, create_parameter, deploy_cfn_template
    ):
        parameter_key = f"param-key-{short_uid()}"
        parameter_value_v0 = f"param-value-{short_uid()}"
        parameter_value_v1 = f"param-value-{short_uid()}"
        parameter_value_v2 = f"param-value-{short_uid()}"

        create_parameter(Name=parameter_key, Type="String", Value=parameter_value_v0)

        v1 = ssm_client.put_parameter(
            Name=parameter_key, Overwrite=True, Type="String", Value=parameter_value_v1
        )
        ssm_client.put_parameter(
            Name=parameter_key, Overwrite=True, Type="String", Value=parameter_value_v2
        )

        result = deploy_cfn_template(
            parameters={"DynamicParameter": f"{parameter_key}:{v1['Version']}"},
            template_path=os.path.join(os.path.dirname(__file__), "../templates/resolve_ssm.yaml"),
        )

        topic_name = result.outputs["TopicName"]
        assert topic_name == parameter_value_v1

    def test_resolve_ssm_secure(self, create_parameter, cfn_client, deploy_cfn_template):
        parameter_key = f"param-key-{short_uid()}"
        parameter_value = f"param-value-{short_uid()}"

        create_parameter(Name=parameter_key, Value=parameter_value, Type="SecureString")

        result = deploy_cfn_template(
            parameters={"DynamicParameter": f"{parameter_key}"},
            template_path=os.path.join(
                os.path.dirname(__file__), "../templates/resolve_ssm_secure.yaml"
            ),
        )

        topic_name = result.outputs["TopicName"]
        assert topic_name == parameter_value


class TestSecretsManagerParameters:
    @pytest.mark.parametrize(
        "template_name",
        [
            "resolve_secretsmanager_full.yaml",
            "resolve_secretsmanager_partial.yaml",
            "resolve_secretsmanager.yaml",
        ],
    )
    def test_resolve_secretsmanager(
        self,
        secretsmanager_client,
        cfn_client,
        create_secret,
        deploy_cfn_template,
        template_name,
    ):
        parameter_key = f"param-key-{short_uid()}"
        parameter_value = f"param-value-{short_uid()}"

        create_secret(Name=parameter_key, SecretString=parameter_value)

        result = deploy_cfn_template(
            parameters={"DynamicParameter": f"{parameter_key}"},
            template_path=os.path.join(os.path.dirname(__file__), "../templates/", template_name),
        )

        topic_name = result.outputs["TopicName"]
        assert topic_name == parameter_value


class TestPreviousValues:
    @pytest.mark.xfail(reason="outputs don't behave well in combination with conditions")
    @pytest.mark.aws_validated
    def test_parameter_usepreviousvalue_behavior(
        self, cfn_client, deploy_cfn_template, is_stack_updated
    ):
        template_path = os.path.join(os.path.dirname(__file__), "../templates/cfn_reuse_param.yaml")

        # 1. create with overridden default value. Due to the condition this should neither create the optional topic,
        # nor the corresponding output
        stack = deploy_cfn_template(template_path=template_path, parameters={"DeployParam": "no"})

        stack_describe_response = cfn_client.describe_stacks(StackName=stack.stack_name)["Stacks"][
            0
        ]
        assert len(stack_describe_response["Outputs"]) == 1

        # 2. update using UsePreviousValue. DeployParam should still be "no", still overriding the default and the only
        # change should be the changed tag on the required topic
        cfn_client.update_stack(
            StackName=stack.stack_namestack_name,
            TemplateBody=load_template_raw(template_path),
            Parameters=[
                {"ParameterKey": "CustomTag", "ParameterValue": "trigger-change"},
                {"ParameterKey": "DeployParam", "UsePreviousValue": True},
            ],
        )
        wait_until(is_stack_updated(stack.stack_id))
        stack_describe_response = cfn_client.describe_stacks(StackName=stack.stack_name)["Stacks"][
            0
        ]
        assert len(stack_describe_response["Outputs"]) == 1

        # 3. update with setting the deployparam to "yes" not. The condition will evaluate to true and thus create the
        # topic + output note: for an even trickier challenge for the cloudformation engine, remove the second parameter
        # key. Behavior should stay the same.
        cfn_client.update_stack(
            StackName=stack.stack_name,
            TemplateBody=load_template_raw(template_path),
            Parameters=[
                {"ParameterKey": "CustomTag", "ParameterValue": "trigger-change-2"},
                {"ParameterKey": "DeployParam", "ParameterValue": "yes"},
            ],
        )
        assert is_stack_updated(stack.stack_id)
        stack_describe_response = cfn_client.describe_stacks(StackName=stack.stack_id)["Stacks"][0]
        assert len(stack_describe_response["Outputs"]) == 2


class TestImportValues:
    @pytest.mark.aws_validated
    def test_import_values_across_stacks(self, deploy_cfn_template, s3_client, cfn_client):
        export_name = f"b-{short_uid()}"

        # create stack #1
        result = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../templates/cfn_function_export.yml"
            ),
            parameters={"BucketExportName": export_name},
        )
        bucket_name1 = result.outputs.get("BucketName1")
        assert bucket_name1

        # create stack #2
        result = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../templates/cfn_function_import.yml"
            ),
            parameters={"BucketExportName": export_name},
        )
        bucket_name2 = result.outputs.get("BucketName2")
        assert bucket_name2

        # assert that correct bucket tags have been created
        tagging = s3_client.get_bucket_tagging(Bucket=bucket_name2)
        test_tag = [tag for tag in tagging["TagSet"] if tag["Key"] == "test"]
        assert test_tag
        assert test_tag[0]["Value"] == bucket_name1

        # TODO support this method
        # assert cfn_client.list_imports(ExportName=export_name)["Imports"]


class TestMacros:
    @pytest.mark.aws_validated
    def test_global_scope(
        self, deploy_cfn_template, cfn_client, create_lambda_function, lambda_client, snapshot
    ):
        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../templates/macros/format_template.py"
        )

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=macro_function_path,
            runtime=Runtime.python3_8,
            client=lambda_client,
            timeout=1,
        )

        macro_name = "SubstitutionMacro"
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../templates/macro_resource.yml"
            ),
            parameters={"FunctionName": func_name, "MacroName": macro_name},
        )

        new_value = f"new-value-{short_uid()}"
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../templates/transformation_global_parameter.yml"
            ),
            parameters={"Substitution": new_value},
        )

        processed_template = cfn_client.get_template(
            StackName=stack.stack_name, TemplateStage="Processed"
        )
        snapshot.add_transformer(snapshot.transform.regex(new_value, "new-value"))
        snapshot.match("processed_template", processed_template)

    @pytest.mark.aws_validated
    @pytest.mark.parametrize(
        "template_to_transform",
        ["transformation_snippet_topic.yml", "transformation_snippet_topic.json"],
    )
    def test_snipped_scope(
        self,
        deploy_cfn_template,
        cfn_client,
        create_lambda_function,
        lambda_client,
        snapshot,
        template_to_transform,
    ):
        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../templates/macros/add_standard_attributes.py"
        )

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=macro_function_path,
            runtime=Runtime.python3_8,
            client=lambda_client,
            timeout=1,
        )

        macro_name = "ConvertTopicToFifo"
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../templates/macro_resource.yml"
            ),
            parameters={"FunctionName": func_name, "MacroName": macro_name},
        )

        topic_name = f"topic-{short_uid()}.fifo"
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../templates/transformation_snippet_topic.yml"
            ),
            parameters={"TopicName": topic_name},
        )

        processed_template = cfn_client.get_template(
            StackName=stack.stack_name, TemplateStage="Processed"
        )
        snapshot.add_transformer(snapshot.transform.regex(topic_name, "topic-name"))
        snapshot.match("processed_template", processed_template)

    @pytest.mark.aws_validated
    def test_scope_order_and_parameters(
        self,
        deploy_cfn_template,
        cfn_client,
        create_lambda_function,
        lambda_client,
        snapshot,
    ):
        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../templates/macros/replace_string.py"
        )

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=macro_function_path,
            runtime=Runtime.python3_8,
            client=lambda_client,
            timeout=1,
        )

        macro_name = "ReplaceString"
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../templates/macro_resource.yml"
            ),
            parameters={"FunctionName": func_name, "MacroName": macro_name},
        )

        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                "../templates/transformation_multiple_scope_parameter.yml",
            ),
        )

        processed_template = cfn_client.get_template(
            StackName=stack.stack_name, TemplateStage="Processed"
        )
        snapshot.match("processed_template", processed_template)

    @pytest.mark.aws_validated
    def test_capabilities_requirements(
        self,
        deploy_cfn_template,
        cfn_client,
        create_lambda_function,
        lambda_client,
        snapshot,
        cleanup_stacks,
    ):

        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../templates/macros/add_role.py"
        )

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=macro_function_path,
            runtime=Runtime.python3_8,
            client=lambda_client,
            timeout=1,
        )

        macro_name = "AddRole"
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../templates/macro_resource.yml"
            ),
            parameters={"FunctionName": func_name, "MacroName": macro_name},
        )

        stack_name = f"stack-{short_uid()}"
        args = {
            "StackName": stack_name,
            "TemplateBody": load_file(
                os.path.join(
                    os.path.dirname(__file__),
                    "../templates/transformation_add_role.yml",
                )
            ),
        }
        with pytest.raises(botocore.exceptions.ClientError) as ex:
            cfn_client.create_stack(**args)
        snapshot.match("error", ex.value.response)

        args["Capabilities"] = [
            "CAPABILITY_AUTO_EXPAND",  # Required to allow macro to add a role to template
            "CAPABILITY_NAMED_IAM",  # Required to allow CFn create added role
        ]
        cfn_client.create_stack(**args)
        cfn_client.get_waiter("stack_create_complete").wait(StackName=stack_name)
        processed_template = cfn_client.get_template(
            StackName=stack_name, TemplateStage="Processed"
        )
        snapshot.add_transformer(snapshot.transform.key_value("RoleName", "role-name"))
        snapshot.match("processed_template", processed_template)
        cleanup_stacks([stack_name])

    def test_validate_lambda_internals(
        self,
        deploy_cfn_template,
        cfn_client,
        create_lambda_function,
        lambda_client,
        snapshot,
        cleanup_stacks,
    ):
        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../templates/macros/print_internals.py"
        )

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=macro_function_path,
            runtime=Runtime.python3_8,
            client=lambda_client,
            timeout=1,
        )

        macro_name = "PrintInternals"
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../templates/macro_resource.yml"
            ),
            parameters={"FunctionName": func_name, "MacroName": macro_name},
        )

        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                "../templates/transformation_print_internals.yml",
            ),
        )

        processed_template = cfn_client.get_template(
            StackName=stack.stack_name, TemplateStage="Processed"
        )
        snapshot.match(
            "event",
            processed_template["TemplateBody"]["Resources"]["Parameter"]["Properties"]["Value"],
        )

    def test_to_validate_template_limit_for_macro(
        self,
        deploy_cfn_template,
        cfn_client,
        create_lambda_function,
        lambda_client,
        snapshot,
    ):
        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../templates/macros/format_template.py"
        )

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=macro_function_path,
            runtime=Runtime.python3_8,
            client=lambda_client,
            timeout=1,
        )

        macro_name = "FormatTemplate"
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../templates/macro_resource.yml"
            ),
            parameters={"FunctionName": func_name, "MacroName": macro_name},
        )

        template_dict = yaml.safe_load(
            load_file(
                os.path.join(
                    os.path.dirname(__file__), "../templates/transformation_global_parameter.yml"
                )
            )
        )

        for n in range(0, 1000):
            pass

        print(template_dict)
