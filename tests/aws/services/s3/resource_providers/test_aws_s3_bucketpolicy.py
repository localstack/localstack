import json
import os

from localstack.testing.pytest import markers


def deploy_stack(deploy_cfn_template, template_filename, **kwargs):
    template_path = os.path.join(os.path.dirname(__file__), "templates", template_filename)
    return deploy_cfn_template(template_path=template_path, **kwargs)


@markers.aws.validated
def test_update_bucket_policy_modify(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "s3_bucketpolicy_all_properties.yml")
    bucket_name = stack.outputs["BucketName"]

    policy = json.loads(aws_client.s3.get_bucket_policy(Bucket=bucket_name)["Policy"])
    snapshot.match("initial_policy_sid", {"Sid": policy["Statement"][0]["Sid"]})

    deploy_stack(
        deploy_cfn_template,
        "s3_bucketpolicy_all_properties_variant.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )

    policy = json.loads(aws_client.s3.get_bucket_policy(Bucket=bucket_name)["Policy"])
    snapshot.match("updated_policy_sid", {"Sid": policy["Statement"][0]["Sid"]})
