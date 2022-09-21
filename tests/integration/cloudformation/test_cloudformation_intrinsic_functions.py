import os

import pytest

from localstack.utils.common import short_uid


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
def test_intrinsic_functions(
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
