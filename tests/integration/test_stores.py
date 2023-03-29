import unittest


@unittest.mock.patch("localstack.config.ALLOW_NONSTANDARD_REGIONS", True)
def test_nonstandard_regions(create_boto_client, monkeypatch):
    """
    Ensure that non-standard AWS regions can be used vertically.
    """
    monkeypatch.setenv("MOTO_ALLOW_NONEXISTENT_REGION", "true")

    # Create a resource in Moto backend
    ec2_client = create_boto_client("ec2", region_name="uranus-south-1")
    ec2_client.create_key_pair(KeyName="foo")

    # Create a resource in LocalStack store
    sqs_client = create_boto_client("sqs", region_name="pluto-central-2a")
    sqs_client.create_queue(QueueName="bar")
