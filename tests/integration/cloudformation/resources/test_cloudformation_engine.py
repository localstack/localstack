import pytest

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


@pytest.mark.aws_validated
def test_implicit_type_conversion(deploy_cfn_template, cfn_client, sqs_client, snapshot):
    snapshot.add_transformer(snapshot.transform.sqs_api())
    stack = deploy_cfn_template(template=TMPL, max_wait=180)
    queue = sqs_client.get_queue_attributes(
        QueueUrl=stack.outputs["QueueUrl"], AttributeNames=["All"]
    )
    snapshot.match("queue", queue)
