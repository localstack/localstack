import json
import os

import jinja2
import pytest
import yaml

from localstack.testing.aws.cloudformation_utils import load_template_file
from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from localstack.utils.sync import retry


# TODO: refactor file and remove this compatibility fn
def load_template_raw(file_name: str):
    return load_template_file(os.path.join(os.path.dirname(__file__), "../templates", file_name))


def test_create_stack_with_ssm_parameters(
    cfn_client, ssm_client, sns_client, cleanup_stacks, is_stack_created
):
    stack_name = f"stack-{short_uid()}"
    parameter_name = f"ls-param-{short_uid()}"
    parameter_value = f"ls-param-value-{short_uid()}"
    parameter_logical_id = "parameter123"
    ssm_client.put_parameter(Name=parameter_name, Value=parameter_value, Type="String")
    template = load_template_raw("dynamicparameter_ssm_string.yaml")
    template_rendered = jinja2.Template(template).render(parameter_name=parameter_name)
    response = cfn_client.create_stack(
        StackName=stack_name,
        TemplateBody=template_rendered,
    )
    stack_id = response["StackId"]
    assert stack_id

    try:
        wait_until(is_stack_created(stack_id))

        created_stack = cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]
        assert created_stack is not None
        assert created_stack["Parameters"][0]["ParameterKey"] == parameter_logical_id
        assert created_stack["Parameters"][0]["ParameterValue"] == parameter_name
        assert created_stack["Parameters"][0]["ResolvedValue"] == parameter_value

        topics = sns_client.list_topics()
        topic_arns = [t["TopicArn"] for t in topics["Topics"]]
        assert any(parameter_value in t for t in topic_arns)
    finally:
        cleanup_stacks([stack_id])
        # TODO: cleanup parameter


def test_list_stack_resources_for_removed_resource(
    cfn_client, is_stack_created, is_change_set_finished
):
    event_bus_name = f"bus-{short_uid()}"
    template = jinja2.Template(load_template_raw("eventbridge_policy.yaml")).render(
        event_bus_name=event_bus_name
    )

    stack_name = f"stack-{short_uid()}"

    response = cfn_client.create_stack(StackName=stack_name, TemplateBody=template)
    stack_id = response["StackId"]
    assert stack_id
    wait_until(is_stack_created(stack_id))

    # get list of stack resources
    resources = cfn_client.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    resources_before = len(resources)
    assert resources_before == 3
    statuses = set([res["ResourceStatus"] for res in resources])
    assert statuses == {"CREATE_COMPLETE"}

    # remove one resource from the template, then update stack (via change set)
    template_dict = yaml.load(template)
    template_dict["Resources"].pop("eventPolicy2")
    template2 = yaml.dump(template_dict)

    response = cfn_client.create_change_set(
        StackName=stack_name, ChangeSetName="cs1", TemplateBody=template2
    )
    change_set_id = response["Id"]
    cfn_client.execute_change_set(ChangeSetName=change_set_id)
    wait_until(is_change_set_finished(change_set_id))

    # get list of stack resources, again - make sure that deleted resource is not contained in result
    resources = cfn_client.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    assert len(resources) == resources_before - 1
    statuses = set([res["ResourceStatus"] for res in resources])
    assert statuses == {"UPDATE_COMPLETE"}


@pytest.mark.xfail(reason="outputs don't behave well in combination with conditions")
@pytest.mark.aws_validated
def test_parameter_usepreviousvalue_behavior(cfn_client, cleanups):
    stack_name = f"stack-{short_uid()}"
    cleanups.append(lambda _: cfn_client.delete_stack(StackName=stack_name))

    # 1. create with overridden default value. Due to the condition this should neither create the optional topic, nor the corresponding output
    create_response = cfn_client.create_stack(
        StackName=stack_name,
        TemplateBody=load_template_raw("cfn_reuse_param.yaml"),
        Parameters=[{"ParameterKey": "DeployParam", "ParameterValue": "no"}],
    )
    stack_id = create_response["StackId"]

    def wait_stack_done():
        return cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"] in [
            "CREATE_COMPLETE",
            "UPDATE_COMPLETE",
        ]

    assert wait_until(wait_stack_done)
    stack_describe_response = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert len(stack_describe_response["Outputs"]) == 1

    # 2. update using UsePreviousValue. DeployParam should still be "no", still overriding the default and the only change should be the changed tag on the required topic
    cfn_client.update_stack(
        StackName=stack_name,
        TemplateBody=load_template_raw("cfn_reuse_param.yaml"),
        Parameters=[
            {"ParameterKey": "CustomTag", "ParameterValue": "trigger-change"},
            {"ParameterKey": "DeployParam", "UsePreviousValue": True},
        ],
    )
    assert wait_until(wait_stack_done)
    stack_describe_response = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert len(stack_describe_response["Outputs"]) == 1

    # 3. update with setting the deployparam to "yes" not. The condition will evaluate to true and thus create the topic + output
    # note: for an even trickier challenge for the cloudformation engine, remove the second parameter key. Behavior should stay the same.
    cfn_client.update_stack(
        StackName=stack_name,
        TemplateBody=load_template_raw("cfn_reuse_param.yaml"),
        Parameters=[
            {"ParameterKey": "CustomTag", "ParameterValue": "trigger-change-2"},
            {"ParameterKey": "DeployParam", "ParameterValue": "yes"},
        ],
    )
    assert wait_until(wait_stack_done)
    stack_describe_response = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert len(stack_describe_response["Outputs"]) == 2


@pytest.mark.aws_validated
def test_stack_time_attributes(cfn_client, deploy_cfn_template):
    api_name = f"test_{short_uid()}"
    template_path = os.path.join(os.path.dirname(__file__), "../templates/simple_api.yaml")

    deployed = deploy_cfn_template(
        template_path=template_path,
        parameters={"ApiName": api_name},
    )
    stack_name = deployed.stack_name
    assert "CreationTime" in cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]

    api_name = f"test_{short_uid()}"
    stack_id = deployed.stack_id
    cfn_client.update_stack(
        StackName=stack_name,
        TemplateBody=load_template_file(template_path),
        Parameters=[{"ParameterKey": "ApiName", "ParameterValue": api_name}],
    )

    def wait_stack_done():
        return cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"] in [
            "CREATE_COMPLETE",
            "UPDATE_COMPLETE",
        ]

    assert wait_until(wait_stack_done)

    assert "LastUpdatedTime" in cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]
    cfn_client.delete_stack(
        StackName=stack_name,
    )
    assert "DeletionTime" in cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]


@pytest.mark.aws_validated
def test_stack_description_special_chars(cfn_client, deploy_cfn_template, snapshot):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    template = """
AWSTemplateFormatVersion: "2010-09-09"
Description: 'test <env>.test.net'
Resources:
  TestResource:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: "100.30.20.0/20"
    """

    deployed = deploy_cfn_template(template=template)
    response = cfn_client.describe_stacks(StackName=deployed.stack_id)["Stacks"][0]
    snapshot.match("describe_stack", response)


@pytest.mark.aws_validated
def test_import_values_across_stacks(deploy_cfn_template, s3_client):
    export_name = f"b-{short_uid()}"

    # create stack #1
    template1 = """
Parameters:
  BucketExportName:
    Type: String
Resources:
  Bucket1:
    Type: AWS::S3::Bucket
    Properties: {}
Outputs:
  BucketName1:
    Value: !Ref Bucket1
    Export:
      Name: !Ref BucketExportName
    """
    result = deploy_cfn_template(template=template1, parameters={"BucketExportName": export_name})
    bucket_name1 = result.outputs.get("BucketName1")
    assert bucket_name1

    # create stack #2
    template2 = """
Parameters:
  BucketExportName:
    Type: String
Resources:
  Bucket2:
    Type: AWS::S3::Bucket
    Properties:
      Tags:
        - Key: test
          Value: !ImportValue
            'Fn::Sub': '${BucketExportName}'
Outputs:
  BucketName2:
    Value: !Ref Bucket2
    """
    result = deploy_cfn_template(template=template2, parameters={"BucketExportName": export_name})
    bucket_name2 = result.outputs.get("BucketName2")
    assert bucket_name2

    # assert that correct bucket tags have been created
    tagging = s3_client.get_bucket_tagging(Bucket=bucket_name2)
    test_tag = [tag for tag in tagging["TagSet"] if tag["Key"] == "test"]
    assert test_tag
    assert test_tag[0]["Value"] == bucket_name1


@pytest.mark.aws_validated
@pytest.mark.parametrize("fileformat", ["yaml", "json"])
def test_get_template(cfn_client, deploy_cfn_template, snapshot, fileformat):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), f"../templates/sns_topic_template.{fileformat}"
        )
    )
    topic_name = stack.outputs["TopicName"]
    snapshot.add_transformer(snapshot.transform.regex(topic_name, "<topic-name>"), priority=-1)

    describe_stacks = cfn_client.describe_stacks(StackName=stack.stack_id)
    snapshot.match("describe_stacks", describe_stacks)

    template_original = cfn_client.get_template(StackName=stack.stack_id, TemplateStage="Original")
    snapshot.match("template_original", template_original)

    template_processed = cfn_client.get_template(
        StackName=stack.stack_id, TemplateStage="Processed"
    )
    snapshot.match("template_processed", template_processed)


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(paths=["$..ParameterValue", "$..PhysicalResourceId"])
def test_stack_update_resources(
    cfn_client,
    deploy_cfn_template,
    is_change_set_finished,
    is_change_set_created_and_available,
    snapshot,
):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.key_value("PhysicalResourceId"))

    def _get_stack_details():
        result = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]
        assert result["StackStatus"] in ["CREATE_COMPLETE", "UPDATE_COMPLETE"]
        return result

    api_name = f"test_{short_uid()}"
    template_path = os.path.join(os.path.dirname(__file__), "../templates/simple_api.yaml")

    # create stack
    deployed = deploy_cfn_template(template_path=template_path, parameters={"ApiName": api_name})
    stack_name = deployed.stack_name
    stack_id = deployed.stack_id

    # assert snapshot of created stack
    result = retry(_get_stack_details, sleep=1, retries=10)
    snapshot.match("stack_created", result)

    # update stack, with one additional resource
    api_name = f"test_{short_uid()}"
    template_body = yaml.safe_load(load_template_file(template_path))
    template_body["Resources"]["Bucket"] = {"Type": "AWS::S3::Bucket"}
    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName="cs1",
        TemplateBody=json.dumps(template_body),
        Parameters=[{"ParameterKey": "ApiName", "ParameterValue": api_name}],
    )
    change_set_id = response["Id"]
    wait_until(is_change_set_created_and_available(change_set_id))
    cfn_client.execute_change_set(ChangeSetName=change_set_id)
    wait_until(is_change_set_finished(change_set_id))

    # assert snapshot of updated stack
    result = retry(_get_stack_details, sleep=1, retries=10)
    snapshot.match("stack_updated", result)

    # describe stack resources
    resources = cfn_client.describe_stack_resources(StackName=stack_name)
    snapshot.match("stack_resources", resources)
