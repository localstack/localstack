import os

from localstack.utils.strings import short_uid


def test_nested_stack_output_refs(cfn_client, deploy_cfn_template, s3_client, s3_create_bucket):
    """test output handling of nested stacks incl. referencing the nested output in the parent stack"""
    bucket_name = s3_create_bucket()
    nested_bucket_name = f"test-bucket-nested-{short_uid()}"
    key = f"test-key-{short_uid()}"
    s3_client.upload_file(
        os.path.join(
            os.path.dirname(__file__), "../templates/nested-stack-output-refs.nested.yaml"
        ),
        Bucket=bucket_name,
        Key=key,
    )
    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/nested-stack-output-refs.yaml"
        ),
        template_mapping={
            "s3_bucket_url": f"/{bucket_name}/{key}",
            "nested_bucket_name": nested_bucket_name,
        },
    )

    nested_stack_id = result.outputs["CustomNestedStackId"]
    nested_stack_details = cfn_client.describe_stacks(StackName=nested_stack_id)
    nested_stack_outputs = nested_stack_details["Stacks"][0]["Outputs"]
    assert "InnerCustomOutput" not in result.outputs
    assert (
        nested_bucket_name
        == [
            o["OutputValue"] for o in nested_stack_outputs if o["OutputKey"] == "InnerCustomOutput"
        ][0]
    )
    assert f"{nested_bucket_name}-suffix" == result.outputs["CustomOutput"]
