from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestResourceAccessManager:
    @markers.snapshot.skip_snapshot_verify(paths=["$..resourceShare.tags"])
    @markers.aws.validated
    def test_basic_crud(self, snapshot, aws_client):
        # Simple snapshot test to ensure the provider is available
        snapshot.add_transformer(snapshot.transform.key_value("name"))
        snapshot.add_transformer(snapshot.transform.key_value("resourceShareArn"))

        name = f"rs-{short_uid()}"
        result = aws_client.ram.create_resource_share(name=name)
        snapshot.match("ram-create-resource-share", result)

        arn = result["resourceShare"]["resourceShareArn"]
        new_name = f"rs-{short_uid()}"

        result = aws_client.ram.update_resource_share(resourceShareArn=arn, name=new_name)
        snapshot.match("ram-update-resource-share", result)

        result = aws_client.ram.delete_resource_share(resourceShareArn=arn)
        snapshot.match("ram-delete-resource-share", result)
