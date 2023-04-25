# Stack
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


def test_skeleton_stack(aws_client, snapshot, cleanups):
    cfn_client = aws_client.cloudformation
    stack_name = f"cfnv2-test-stack-{short_uid()}"

    change_set_result = cfn_client.create_stack(
        StackName=stack_name,
        TemplateBody=TEMPLATE,
        Parameters=[
            {"ParameterKey": "TagValue", "ParameterValue": "tag1"},
        ]
    )
    stack_arn = change_set_result['StackId']
    cleanups.append(lambda: cfn_client.delete_stack(StackName=stack_arn))

    cfn_client.get_waiter("stack_create_complete").wait(StackName=stack_arn)

    postcreate_original_template = cfn_client.get_template(StackName=stack_name, TemplateStage="Original")
    snapshot.match("postcreate_original_template", postcreate_original_template)
    postcreate_processed_template = cfn_client.get_template(StackName=stack_name, TemplateStage="Processed")
    snapshot.match("postcreate_processed_template", postcreate_processed_template)
    describe_stack = cfn_client.describe_stacks(StackName=stack_arn)
    snapshot.match("describe_stack", describe_stack)
