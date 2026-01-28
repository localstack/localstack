import os
from typing import Literal

import pytest

from localstack.config import S3_STATIC_WEBSITE_HOSTNAME
from localstack.constants import AWS_REGION_US_EAST_1
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.urls import localstack_host


@pytest.fixture
def record_set_transformers(snapshot):
    snapshot.add_transformers_list(
        [
            snapshot.transform.jsonpath(
                "$..ResourceRecords..Value.[*]", value_replacement="resource-record"
            ),
            snapshot.transform.jsonpath(
                "$..ResourceRecordSets..Name", value_replacement="record-name"
            ),
        ]
    )


@pytest.fixture
def get_s3_website_host_and_hosted_zone_id(aws_client_factory, s3_create_bucket_with_client):
    # to be able to deploy an AliasTarget in AWS, we need a valid target. We will use an S3 bucket here
    # The HostedZoneId field depends on the region the bucket is deployed in
    # See https://docs.aws.amazon.com/general/latest/gr/s3.html#auto-endpoints-website-s3

    s3_hosted_zone_ids = {
        AWS_REGION_US_EAST_1: "Z3AQBSTGFYJSTF",
        "us-west-1": "Z2F56UZL2M1ACD",
    }

    def _create_s3_website(region_name: Literal["us-east-1", "us-west-1"]):
        bucket_name = f"bucket-cfn-{short_uid()}"
        hosted_zone_id = s3_hosted_zone_ids[region_name]

        s3_client = aws_client_factory(region_name=region_name).s3
        s3_params = {}
        if region_name != AWS_REGION_US_EAST_1:
            s3_params["CreateBucketConfiguration"] = {"LocationConstraint": region_name}
        s3_create_bucket_with_client(s3_client, Bucket=bucket_name, **s3_params)
        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
            },
        )
        if is_aws_cloud():
            # beware if adding more regions, it can be `-` or `.` between the `s3-website` and the region name
            s3_website_url = f"{bucket_name}.s3-website-{region_name}.amazonaws.com"
        else:
            s3_website_url = f"{bucket_name}.{S3_STATIC_WEBSITE_HOSTNAME}:{localstack_host().port}"

        return s3_website_url, hosted_zone_id

    yield _create_s3_website


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        # Moto returns a different value (300 instead of 100) when not provided
        "$..MaxItems",
        # Different hardcoded value in the SOA record compared to Amazon
        "$..ResourceRecordSets.[2].ResourceRecords.[0].Value",
    ]
)
def test_create_record_set_via_id(
    route53_hosted_zone, aws_client, deploy_cfn_template, snapshot, record_set_transformers
):
    create_zone_response = route53_hosted_zone()
    hosted_zone_id = create_zone_response["HostedZone"]["Id"]
    route53_name = create_zone_response["HostedZone"]["Name"]
    parameters = {"HostedZoneId": hosted_zone_id, "Name": route53_name}
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/route53_hostedzoneid_template.yaml"
        ),
        parameters=parameters,
        max_wait=300,
    )
    rr_sets = aws_client.route53.list_resource_record_sets(HostedZoneId=hosted_zone_id)
    snapshot.match("record-sets", rr_sets)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        # Moto returns a different value (300 instead of 100) when not provided
        "$..MaxItems",
        # Different hardcoded value in the SOA record compared to Amazon
        "$..ResourceRecordSets.[2].ResourceRecords.[0].Value",
    ]
)
def test_create_record_set_via_name(
    deploy_cfn_template, aws_client, route53_hosted_zone, snapshot, record_set_transformers
):
    create_zone_response = route53_hosted_zone()
    route53_name = create_zone_response["HostedZone"]["Name"]
    parameters = {"HostedZoneName": route53_name, "Name": route53_name}
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/route53_hostedzonename_template.yaml"
        ),
        parameters=parameters,
    )
    rr_sets = aws_client.route53.list_resource_record_sets(
        HostedZoneId=create_zone_response["HostedZone"]["Id"]
    )
    snapshot.match("record-sets", rr_sets)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        # Moto returns a different value (300 instead of 100) when not provided
        "$..MaxItems",
        # Different hardcoded value in the SOA record compared to Amazon
        "$..ResourceRecordSets.[2].ResourceRecords.[0].Value",
    ]
)
def test_create_record_set_without_resource_record(
    deploy_cfn_template, aws_client, route53_hosted_zone, snapshot, record_set_transformers
):
    create_zone_response = route53_hosted_zone()
    hosted_zone_id = create_zone_response["HostedZone"]["Id"]
    route53_name = create_zone_response["HostedZone"]["Name"]
    parameters = {"HostedZoneId": hosted_zone_id, "Name": route53_name}
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__),
            "../../../templates/route53_recordset_without_resource_records.yaml",
        ),
        parameters=parameters,
    )
    rr_sets = aws_client.route53.list_resource_record_sets(HostedZoneId=hosted_zone_id)
    snapshot.match("record-sets", rr_sets)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        # Moto returns a different value (300 instead of 100) when not provided
        "$..MaxItems",
        # Different hardcoded value in the SOA record compared to Amazon
        "$..ResourceRecordSets.[3].ResourceRecords.[0].Value",
    ]
)
def test_create_multiple_weighted_alias_target_record_sets(
    route53_hosted_zone,
    aws_client,
    deploy_cfn_template,
    snapshot,
    record_set_transformers,
    get_s3_website_host_and_hosted_zone_id,
):
    snapshot.add_transformer(snapshot.transform.key_value("DNSName"))
    bucket_1_host, bucket_1_hosted_zone_id = get_s3_website_host_and_hosted_zone_id(
        AWS_REGION_US_EAST_1
    )
    bucket_2_host, bucket_2_hosted_zone_id = get_s3_website_host_and_hosted_zone_id("us-west-1")
    create_zone_response = route53_hosted_zone()
    hosted_zone_id = create_zone_response["HostedZone"]["Id"]
    route53_name = create_zone_response["HostedZone"]["Name"]
    parameters = {
        "HostedZoneId": hosted_zone_id,
        "Name": route53_name,
        "BucketRegionOneHost": bucket_1_host,
        "BucketRegionOneHostedZoneId": bucket_1_hosted_zone_id,
        "BucketRegionTwoHost": bucket_2_host,
        "BucketRegionTwoHostedZoneId": bucket_2_hosted_zone_id,
    }

    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__),
            "../../../templates/route53_hostedzoneid_weighted_template.yaml",
        ),
        parameters=parameters,
        max_wait=300 if is_aws_cloud() else 60,
    )
    rr_sets = aws_client.route53.list_resource_record_sets(HostedZoneId=hosted_zone_id)
    snapshot.match("record-sets", rr_sets)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        # Moto returns a different value (300 instead of 100) when not provided
        "$..MaxItems",
        # Different hardcoded value in the SOA record compared to Amazon
        "$..ResourceRecordSets.[3].ResourceRecords.[0].Value",
    ]
)
def test_update_multiple_weighted_alias_target_record_sets(
    route53_hosted_zone,
    aws_client,
    deploy_cfn_template,
    snapshot,
    record_set_transformers,
    get_s3_website_host_and_hosted_zone_id,
):
    snapshot.add_transformer(snapshot.transform.key_value("DNSName"))
    bucket_1_host, bucket_1_hosted_zone_id = get_s3_website_host_and_hosted_zone_id(
        AWS_REGION_US_EAST_1
    )
    bucket_2_host, bucket_2_hosted_zone_id = get_s3_website_host_and_hosted_zone_id("us-west-1")
    create_zone_response = route53_hosted_zone()
    hosted_zone_id = create_zone_response["HostedZone"]["Id"]
    route53_name = create_zone_response["HostedZone"]["Name"]
    parameters = {
        "HostedZoneId": hosted_zone_id,
        "Name": route53_name,
        "BucketRegionOneHost": bucket_1_host,
        "BucketRegionOneHostedZoneId": bucket_1_hosted_zone_id,
        "BucketRegionTwoHost": bucket_2_host,
        "BucketRegionTwoHostedZoneId": bucket_2_hosted_zone_id,
    }
    template_path = os.path.join(
        os.path.dirname(__file__),
        "../../../templates/route53_hostedzoneid_weighted_template.yaml",
    )

    result = deploy_cfn_template(
        template_path=template_path,
        parameters=parameters,
        max_wait=300 if is_aws_cloud() else 60,
    )
    stack_name = result.stack_name
    rr_sets = aws_client.route53.list_resource_record_sets(HostedZoneId=hosted_zone_id)
    snapshot.match("record-sets", rr_sets)

    parameters["WeightBucketOne"] = "50"
    parameters["WeightBucketTwo"] = "100"

    deploy_cfn_template(
        template_path=template_path,
        parameters=parameters,
        max_wait=300 if is_aws_cloud() else 60,
        is_update=True,
        stack_name=stack_name,
    )
    rr_sets = aws_client.route53.list_resource_record_sets(HostedZoneId=hosted_zone_id)
    snapshot.match("record-sets-update-weights", rr_sets)

    parameters["BucketRegionTwoHost"] = bucket_1_host
    parameters["BucketRegionTwoHostedZoneId"] = bucket_1_hosted_zone_id

    deploy_cfn_template(
        template_path=template_path,
        parameters=parameters,
        max_wait=300 if is_aws_cloud() else 60,
        is_update=True,
        stack_name=stack_name,
    )
    rr_sets = aws_client.route53.list_resource_record_sets(HostedZoneId=hosted_zone_id)
    snapshot.match("record-sets-update-alias-target", rr_sets)

    parameters["BucketTwoSetIdentifier"] = "region-3"

    deploy_cfn_template(
        template_path=template_path,
        parameters=parameters,
        max_wait=300 if is_aws_cloud() else 60,
        is_update=True,
        stack_name=stack_name,
    )
    rr_sets = aws_client.route53.list_resource_record_sets(HostedZoneId=hosted_zone_id)
    snapshot.match("record-sets-update-set-identifier", rr_sets)
