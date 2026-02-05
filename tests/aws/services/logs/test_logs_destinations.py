"""Tests for CloudWatch Logs - Destination operations (cross-account log delivery)."""

import json

import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.common import short_uid
from localstack.utils.sync import retry

ACCESS_POLICY_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "logs.us-east-1.amazonaws.com"},
                "Action": "logs:PutSubscriptionFilter",
                "Resource": "destination_arn",
            }
        ],
    }
)


@pytest.fixture
def kinesis_stream_arn(aws_client, kinesis_create_stream, wait_for_stream_ready) -> str:
    stream_name = kinesis_create_stream()
    wait_for_stream_ready(stream_name)
    return aws_client.kinesis.describe_stream(StreamName=stream_name)["StreamDescription"][
        "StreamARN"
    ]


@pytest.fixture
def destination_role(aws_client, create_iam_role_with_policy, kinesis_stream_arn):
    role = create_iam_role_with_policy(
        RoleName=f"role-logs-{short_uid()}",
        PolicyName=f"policy-logs-{short_uid()}",
        RoleDefinition={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "logs.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        PolicyDefinition={
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "kinesis:*", "Resource": kinesis_stream_arn}
            ],
        },
    )

    if is_aws_cloud():
        # This operation is to confirm role propagation withing AWS
        def _assume_role():
            try:
                aws_client.sts.assume_role(
                    RoleArn=role,
                    RoleSessionName="check",
                )
                return True
            except Exception:
                # AccessDenied means role exists but we can't assume it (expected for service roles)
                # Other errors might mean role not propagated yet
                return False

        retry(_assume_role, sleep_before=1, sleep=2, retries=10)
    return role


def _retry_put_destination(aws_client, **kwargs):
    def put_destination():
        resp = aws_client.logs.put_destination(
            destinationName=kwargs["destinationName"],
            targetArn=kwargs["targetArn"],
            roleArn=kwargs["roleArn"],
            tags=kwargs.get("tags", {"tag": "test"}),
        )
        return resp

    return retry(put_destination, retries=5, sleep=3 if is_aws_cloud() else 1)


class TestDestinations:
    """Tests for destination operations."""

    @markers.aws.validated
    def test_put_destination(
        self, aws_client, snapshot, cleanups, kinesis_stream_arn, destination_role
    ):
        """Test creating a destination."""
        destination_name = f"test-destination-{short_uid()}"
        role_arn = destination_role
        target_arn = kinesis_stream_arn

        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.regex(destination_name, "<destination>"))
        snapshot.add_transformer(snapshot.transform.regex(role_arn.split("/")[-1], "<role-name>"))
        snapshot.add_transformer(
            snapshot.transform.regex(target_arn.split("/")[-1], "<stream-name>")
        )

        response = _retry_put_destination(
            aws_client,
            destinationName=destination_name,
            targetArn=target_arn,
            roleArn=role_arn,
            tags={"Name": destination_name},
        )
        cleanups.append(
            lambda: aws_client.logs.delete_destination(destinationName=destination_name)
        )

        # IAM Role takes time to propagate in AWS causing a client error
        snapshot.match("put-destination", response)

    @markers.aws.validated
    def test_describe_destinations_empty(self, aws_client, snapshot):
        """Test describing destinations when none exist with a given prefix."""
        response = aws_client.logs.describe_destinations(
            DestinationNamePrefix=f"non-existent-{short_uid()}"
        )
        snapshot.match("describe-destinations-empty", response)

    @markers.aws.validated
    def test_describe_destinations_with_prefix(
        self, aws_client, snapshot, destination_role, kinesis_stream_arn, cleanups
    ):
        """Test describing destinations with prefix filter."""
        prefix = f"test-dest-{short_uid()}"
        role_arn = destination_role
        target_arn = kinesis_stream_arn

        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.regex(prefix, "<destination>"))
        snapshot.add_transformer(snapshot.transform.regex(role_arn.split("/")[-1], "<role-name>"))
        snapshot.add_transformer(
            snapshot.transform.regex(target_arn.split("/")[-1], "<stream-name>")
        )

        _retry_put_destination(
            aws_client,
            destinationName=prefix,
            targetArn=target_arn,
            roleArn=role_arn,
            tags={"Name": prefix},
        )
        cleanups.append(lambda: aws_client.logs.delete_destination(destinationName=prefix))

        response = aws_client.logs.describe_destinations(DestinationNamePrefix=prefix)
        snapshot.match("describe-destinations", response)

    @markers.aws.validated
    def test_update_destination(
        self, aws_client, snapshot, destination_role, kinesis_stream_arn, cleanups
    ):
        """Test updating a destination's target and role ARNs."""
        destination_name = f"test-destination-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.regex(destination_name, "<destination>"))
        snapshot.add_transformer(
            snapshot.transform.regex(destination_role.split("/")[-1], "<role-name>")
        )
        snapshot.add_transformer(
            snapshot.transform.regex(kinesis_stream_arn.split("/")[-1], "<stream-name>")
        )

        _retry_put_destination(
            aws_client,
            destinationName=destination_name,
            roleArn=destination_role,
            targetArn=kinesis_stream_arn,
        )
        cleanups.append(
            lambda: aws_client.logs.delete_destination(destinationName=destination_name)
        )

        response = aws_client.logs.describe_destinations(DestinationNamePrefix=destination_name)
        snapshot.match("original-description", response)

        # Update destination
        _retry_put_destination(
            aws_client,
            destinationName=destination_name,
            roleArn=destination_role,
            targetArn=kinesis_stream_arn,
            tags={"tag1": "value1"},
        )

        # Verify update
        response = aws_client.logs.describe_destinations(DestinationNamePrefix=destination_name)
        snapshot.match("updated-description", response)

    @markers.aws.validated
    def test_put_destination_policy(
        self, aws_client, snapshot, destination_role, kinesis_stream_arn, cleanups
    ):
        """Test setting an access policy on a destination."""
        destination_name = f"test-destination-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.regex(destination_name, "<destination>"))
        snapshot.add_transformer(
            snapshot.transform.regex(destination_role.split("/")[-1], "<role-name>")
        )
        snapshot.add_transformer(
            snapshot.transform.regex(kinesis_stream_arn.split("/")[-1], "<stream-name>")
        )

        _retry_put_destination(
            aws_client,
            destinationName=destination_name,
            targetArn=kinesis_stream_arn,
            roleArn=destination_role,
        )
        cleanups.append(
            lambda: aws_client.logs.delete_destination(destinationName=destination_name)
        )

        # Put access policy
        policy = ACCESS_POLICY_DOC.replace("destination_arn", kinesis_stream_arn)

        response = aws_client.logs.put_destination_policy(
            destinationName=destination_name, accessPolicy=policy
        )
        snapshot.match("put-destination-policy", response)

        # Verify policy is set
        response = aws_client.logs.describe_destinations(DestinationNamePrefix=destination_name)
        snapshot.match("destination-with-policy", response)

    @markers.aws.validated
    def test_delete_destination(
        self, aws_client, destination_role, kinesis_stream_arn, snapshot, cleanups
    ):
        """Test deleting a destination."""
        destination_name = f"test-dest-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.regex(destination_name, "<destination>"))
        snapshot.add_transformer(
            snapshot.transform.regex(destination_role.split("/")[-1], "<role-name>")
        )
        snapshot.add_transformer(
            snapshot.transform.regex(kinesis_stream_arn.split("/")[-1], "<stream-name>")
        )

        _retry_put_destination(
            aws_client,
            destinationName=destination_name,
            targetArn=kinesis_stream_arn,
            roleArn=destination_role,
        )

        # Delete destination
        response = aws_client.logs.delete_destination(destinationName=destination_name)
        snapshot.match("delete-destination", response)

        # Verify deletion
        response = aws_client.logs.describe_destinations(DestinationNamePrefix=destination_name)
        snapshot.match("no-destination-found", response)


class TestDestinationsTags:
    """Tests for destination tagging operations."""

    @markers.aws.validated
    @pytest.mark.skip(reason="not supported")
    def test_destination_tags(
        self, aws_client, snapshot, cleanups, destination_role, kinesis_stream_arn
    ):
        """Test tagging operations on destinations."""
        destination_name = f"test-destination-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.regex(destination_name, "<destination>"))
        snapshot.add_transformer(
            snapshot.transform.regex(destination_role.split("/")[-1], "<role-name>")
        )
        snapshot.add_transformer(
            snapshot.transform.regex(kinesis_stream_arn.split("/")[-1], "<stream-name>")
        )

        # Create destination with initial tag
        response = _retry_put_destination(
            aws_client,
            destinationName=destination_name,
            targetArn=kinesis_stream_arn,
            roleArn=destination_role,
            tags={"key1": "val1"},
        )
        destination_arn = response["destination"]["arn"]
        cleanups.append(
            lambda: aws_client.logs.delete_destination(destinationName=destination_name)
        )

        # Add more tags
        aws_client.logs.tag_resource(resourceArn=destination_arn, tags={"key2": "val2"})

        # List tags
        response = aws_client.logs.list_tags_for_resource(resourceArn=destination_arn)
        snapshot.match("list-tags-after-add", response)
        assert response["tags"] == {"key1": "val1", "key2": "val2"}

        # Remove a tag
        aws_client.logs.untag_resource(resourceArn=destination_arn, tagKeys=["key2"])

        response = aws_client.logs.list_tags_for_resource(resourceArn=destination_arn)
        snapshot.match("list-tags-after-remove", response)
        assert response["tags"] == {"key1": "val1"}
