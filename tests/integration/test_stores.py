from localstack.utils.strings import short_uid


def test_nonstandard_regions(monkeypatch, aws_client_factory):
    """
    Ensure that non-standard AWS regions can be used vertically.
    """
    monkeypatch.setenv("MOTO_ALLOW_NONEXISTENT_REGION", "true")
    monkeypatch.setattr("localstack.config.ALLOW_NONSTANDARD_REGIONS", True)

    # Create a resource in Moto backend
    ec2_client = aws_client_factory(region_name="uranus-south-1").ec2
    key_name = f"k-{short_uid()}"
    ec2_client.create_key_pair(KeyName=key_name)
    assert ec2_client.describe_key_pairs(KeyNames=[key_name])

    # Create a resource in LocalStack store
    sqs_client = aws_client_factory(region_name="pluto-central-2a").sqs
    queue_name = f"q-{short_uid()}"
    sqs_client.create_queue(QueueName=queue_name)
    queue_url = sqs_client.get_queue_url(QueueName=queue_name)["QueueUrl"]
    sqs_client.delete_queue(QueueUrl=queue_url)
