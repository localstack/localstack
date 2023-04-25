import time
from threading import Thread

import pytest

from localstack.utils.strings import short_uid


TEMPLATE = """
Parameters:
    ResName:
        Type: String
    TagValue:
        Type: String
Resources:
    MyBucket:
        Type: AWS::SNS::Topic
        Properties:
            TopicName: !Ref ResName
            Tags:
                - Key: CustomTag
                  Value: !Ref TagValue
"""


def test_basic(aws_client, snapshot, cleanups):
    cfn_client = aws_client.cloudformation
    stack_name = f"cfnv2-test-stack-{short_uid()}"
    change_set_name = f"cfnv2-test-changeset-{short_uid()}"
    res_name = f"cfnv2-test-topic-{short_uid()}"


    change_set_result = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=TEMPLATE,
        ChangeSetType="CREATE",
        Parameters=[
            {"ParameterKey": "ResName", "ParameterValue": res_name},
            {"ParameterKey": "TagValue", "ParameterValue": "tag1"},
        ]
    )
    change_set_arn = change_set_result['Id']
    stack_arn = change_set_result['StackId']
    cleanups.append(lambda: cfn_client.delete_stack(StackName=stack_arn))


    describe_stack = cfn_client.describe_stacks(StackName=stack_arn)
    snapshot.match("describe_stack", describe_stack)
    describe_changeset_byarnalone = cfn_client.describe_change_set(ChangeSetName=change_set_arn)
    snapshot.match("describe_changeset_byarnalone", describe_changeset_byarnalone)
    cfn_client.get_waiter("change_set_create_complete").wait(ChangeSetName=change_set_arn)
    describe_changeset_bynames_postwait = cfn_client.describe_change_set(ChangeSetName=change_set_name, StackName=stack_name)
    snapshot.match("describe_changeset_bynames_postwait", describe_changeset_bynames_postwait)

    # execute changeset
    cfn_client.execute_change_set(ChangeSetName=change_set_arn)
    cfn_client.get_waiter("stack_create_complete").wait(StackName=stack_arn)
    describe_stack_postexecute = cfn_client.describe_stacks(StackName=stack_arn)
    snapshot.match("describe_stack_postexecute", describe_stack_postexecute)
    postcreate_original_template = cfn_client.get_template(StackName=stack_name, ChangeSetName=change_set_name, TemplateStage="Original")
    snapshot.match("postcreate_original_template", postcreate_original_template)
    postcreate_processed_template = cfn_client.get_template(StackName=stack_name, ChangeSetName=change_set_name, TemplateStage="Processed")
    snapshot.match("postcreate_processed_template", postcreate_processed_template)

    # update a value
    update_change_set_name = f"{change_set_name}-update1"
    create_update_change_set = cfn_client.create_change_set(
        ChangeSetName=update_change_set_name,
        StackName=stack_name,
        UsePreviousTemplate=True,
        Parameters=[
            {"ParameterKey": "ResName", "ParameterValue": res_name},
            {"ParameterKey": "TagValue", "ParameterValue": "tag2"},
        ]
    )
    update_change_set_arn = create_update_change_set['Id']
    snapshot.match("create_update_change_set", create_update_change_set)
    cfn_client.get_waiter("change_set_create_complete").wait(ChangeSetName=update_change_set_arn)

    describe_update_change_set = cfn_client.describe_change_set(ChangeSetName=update_change_set_arn)
    snapshot.match("describe_update_change_set", describe_update_change_set)
    
    postupdate_original_template = cfn_client.get_template(StackName=stack_name, ChangeSetName=update_change_set_name, TemplateStage="Original")
    snapshot.match("postupdate_original_template", postupdate_original_template)
    postupdate_processed_template = cfn_client.get_template(StackName=stack_name, ChangeSetName=update_change_set_name, TemplateStage="Processed")
    snapshot.match("postupdate_processed_template", postupdate_processed_template)

    print("done")



