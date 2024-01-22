import os

from localstack.testing.pytest import markers


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..KeyPairs..KeyType",
        "$..KeyPairs..Tags",
        "$..BlockDeviceMappings..Ebs.VolumeId",
        "$..BootMode",
        "$..CapacityReservationSpecification",
        "$..ClientToken",
        "$..CpuOptions",
        "$..CurrentInstanceBootMode",
        "$..EnaSupport",
        "$..EnclaveOptions",
        "$..HibernationOptions",
        "$..KernelId",
        "$..MaintenanceOptions",
        "$..MetadataOptions",
        "$..NetworkInterfaces",
        "$..PlatformDetails",
        "$..PrivateDnsName",
        "$..PrivateDnsNameOptions",
        "$..PrivateIpAddress",
        "$..ProductCodes",
        "$..PublicDnsName",
        "$..PublicIpAddress",
        "$..RootDeviceName",
        "$..SecurityGroups",
        "$..StateReason",
        "$..Tags",
        "$..UsageOperation",
        "$..UsageOperationUpdateTime",
        "$..VirtualizationType",
        "$..BlockDeviceMappings..DeviceName",
        "$..BlockDeviceMappings..Ebs.Status",
        "$..Placement.AvailabilityZone",
    ]
)
def test_deploy_instance_with_key_pair(deploy_cfn_template, aws_client, snapshot):
    snapshot.add_transformer(snapshot.transform.key_value("KeyName"))
    snapshot.add_transformer(snapshot.transform.key_value("KeyPairId"))
    snapshot.add_transformer(snapshot.transform.key_value("KeyFingerprint"))
    snapshot.add_transformer(snapshot.transform.key_value("InstanceId"))
    snapshot.add_transformer(snapshot.transform.key_value("ImageId"))
    snapshot.add_transformer(snapshot.transform.key_value("VpcId"))
    snapshot.add_transformer(snapshot.transform.key_value("SubnetId"))

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../../templates/ec2_instance_keypair.yml"
        )
    )

    key_name = stack.outputs["KeyPairName"]
    instance_id = stack.outputs["InstanceId"]

    response = aws_client.ec2.describe_instances(InstanceIds=[instance_id])
    snapshot.match("instance", response["Reservations"][0]["Instances"][0])

    response = aws_client.ec2.describe_key_pairs(KeyNames=[key_name])
    snapshot.match("key_pair", response)
