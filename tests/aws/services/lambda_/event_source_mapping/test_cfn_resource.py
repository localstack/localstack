import json
import os

from localstack.testing.pytest import markers
from localstack.testing.scenario.provisioning import cleanup_s3_bucket
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..Tags.'aws:cloudformation:logical-id'",
        "$..Tags.'aws:cloudformation:stack-id'",
        "$..Tags.'aws:cloudformation:stack-name'",
    ]
)
def test_adding_tags(deploy_cfn_template, aws_client, snapshot, cleanups):
    template_path = os.path.join(
        os.path.join(os.path.dirname(__file__), "../../../templates/event_source_mapping_tags.yml")
    )
    assert os.path.isfile(template_path)

    output_key = f"key-{short_uid()}"
    stack = deploy_cfn_template(
        template_path=template_path,
        parameters={"OutputKey": output_key},
    )
    # ensure the S3 bucket is empty so we can delete it
    cleanups.append(lambda: cleanup_s3_bucket(aws_client.s3, stack.outputs["OutputBucketName"]))

    snapshot.add_transformer(snapshot.transform.regex(stack.stack_id, "<stack-id>"))
    snapshot.add_transformer(snapshot.transform.regex(stack.stack_name, "<stack-name>"))

    event_source_mapping_arn = stack.outputs["EventSourceMappingArn"]
    tags_response = aws_client.lambda_.list_tags(Resource=event_source_mapping_arn)
    snapshot.match("event-source-mapping-tags", tags_response)

    # check the mapping works
    queue_url = stack.outputs["QueueUrl"]
    aws_client.sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps({"body": "something"}),
    )

    retry(
        lambda: aws_client.s3.head_object(Bucket=stack.outputs["OutputBucketName"], Key=output_key),
        retries=10,
        sleep=5.0,
    )
