"""Tests for CloudWatch Logs - Delivery operations (vended logs delivery)."""

import json

import pytest

from localstack.testing.pytest import markers
from localstack.utils.common import short_uid


def get_delivery_destination_policy(region: str, account_id: str) -> str:
    """Generate a delivery destination policy document."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowLogDeliveryActions",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "logs:CreateDelivery",
                    "Resource": [
                        f"arn:aws:logs:{region}:{account_id}:delivery-source:*",
                        f"arn:aws:logs:{region}:{account_id}:delivery:*",
                        f"arn:aws:logs:{region}:{account_id}:delivery-destination:*",
                    ],
                }
            ],
        }
    )


class TestDeliveryDestinations:
    """Tests for delivery destination operations."""

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..deliveryDestination.tags"])
    def test_put_delivery_destination(self, aws_client, snapshot, cleanups, s3_bucket):
        """Test creating a delivery destination."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        destination_name = f"test-dd-{short_uid()}"

        response = aws_client.logs.put_delivery_destination(
            name=destination_name,
            outputFormat="json",
            deliveryDestinationConfiguration={
                "destinationResourceArn": f"arn:aws:s3:::{s3_bucket}"
            },
            tags={"key1": "value1"},
        )
        cleanups.append(lambda: aws_client.logs.delete_delivery_destination(name=destination_name))
        snapshot.add_transformer(snapshot.transform.regex(destination_name, "<destination-name>"))
        snapshot.add_transformer(snapshot.transform.regex(s3_bucket, "<bucket>"))
        snapshot.match("put-delivery-destination", response)

    @markers.aws.validated
    def test_put_delivery_destination_invalid_format(self, aws_client, snapshot, s3_bucket):
        """Test creating a delivery destination with invalid output format."""
        with pytest.raises(Exception) as ctx:
            aws_client.logs.put_delivery_destination(
                name=f"test-dd-{short_uid()}",
                outputFormat="foobar",  # Invalid format
                deliveryDestinationConfiguration={
                    "destinationResourceArn": f"arn:aws:s3:::{s3_bucket}"
                },
            )
        snapshot.match("error-invalid-format", ctx.value.response)

    @markers.aws.validated
    def test_put_delivery_destination_update(
        self, aws_client, snapshot, cleanups, s3_bucket, s3_create_bucket
    ):
        """Test updating a delivery destination."""
        destination_name = f"test-dd-{short_uid()}"
        second_bucket = s3_create_bucket()

        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.regex(destination_name, "<destination-name>"))
        snapshot.add_transformer(snapshot.transform.regex(second_bucket, "<second-bucket>"))

        # Create initial destination
        aws_client.logs.put_delivery_destination(
            name=destination_name,
            deliveryDestinationConfiguration={
                "destinationResourceArn": f"arn:aws:s3:::{s3_bucket}"
            },
        )
        cleanups.append(lambda: aws_client.logs.delete_delivery_destination(name=destination_name))

        # Update destination resource
        response = aws_client.logs.put_delivery_destination(
            name=destination_name,
            deliveryDestinationConfiguration={
                "destinationResourceArn": f"arn:aws:s3:::{second_bucket}"
            },
        )
        snapshot.match("put-delivery-destination-update", response)

    @markers.aws.validated
    def test_get_delivery_destination(self, aws_client, snapshot, cleanups, s3_bucket):
        """Test getting a delivery destination."""

        destination_name = f"test-dd-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.regex(destination_name, "<destination-name>"))
        snapshot.add_transformer(snapshot.transform.regex(s3_bucket, "<bucket>"))

        aws_client.logs.put_delivery_destination(
            name=destination_name,
            deliveryDestinationConfiguration={
                "destinationResourceArn": f"arn:aws:s3:::{s3_bucket}"
            },
        )
        cleanups.append(lambda: aws_client.logs.delete_delivery_destination(name=destination_name))

        response = aws_client.logs.get_delivery_destination(name=destination_name)
        snapshot.match("get-delivery-destination", response)
        assert response["deliveryDestination"]["name"] == destination_name

    @markers.aws.validated
    def test_get_delivery_destination_not_found(self, aws_client, snapshot):
        """Test getting a non-existent delivery destination."""
        with pytest.raises(Exception) as ctx:
            aws_client.logs.get_delivery_destination(name="foobar")
        snapshot.match("error-not-found", ctx.value.response)

    @markers.aws.validated
    def test_describe_delivery_destinations(self, aws_client, snapshot, cleanups, s3_bucket):
        """Test describing delivery destinations."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.regex(s3_bucket, "<bucket>"))
        destinations = []

        for i in range(2):
            destination_name = f"test-dd-{short_uid()}-{i}"
            aws_client.logs.put_delivery_destination(
                name=destination_name,
                deliveryDestinationConfiguration={
                    "destinationResourceArn": f"arn:aws:s3:::{s3_bucket}"
                },
            )
            destinations.append(destination_name)
            cleanups.append(
                lambda dn=destination_name: aws_client.logs.delete_delivery_destination(name=dn)
            )
            snapshot.add_transformer(
                snapshot.transform.regex(destination_name, f"<destination-{i}>")
            )

        response = aws_client.logs.describe_delivery_destinations()
        descriptions = [
            desc for desc in response["deliveryDestinations"] if desc["name"] in destinations
        ]

        snapshot.match("describe-delivery-destinations", descriptions)

    @markers.aws.validated
    def test_delete_delivery_destination(self, aws_client, snapshot, cleanups, s3_bucket):
        """Test deleting a delivery destination."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        destination_name = f"test-dd-{short_uid()}"

        aws_client.logs.put_delivery_destination(
            name=destination_name,
            deliveryDestinationConfiguration={
                "destinationResourceArn": f"arn:aws:s3:::{s3_bucket}"
            },
        )

        # Delete destination
        aws_client.logs.delete_delivery_destination(name=destination_name)

        # Verify deletion
        with pytest.raises(Exception) as ctx:
            aws_client.logs.get_delivery_destination(name=destination_name)
        snapshot.match("error-after-delete", ctx.value.response)

    @markers.aws.validated
    def test_delete_delivery_destination_not_found(self, aws_client, snapshot):
        """Test deleting a non-existent delivery destination."""
        with pytest.raises(Exception) as ctx:
            aws_client.logs.delete_delivery_destination(name="foobar")
        snapshot.match("error-not-found", ctx.value.response)


class TestDeliveryDestinationPolicies:
    """Tests for delivery destination policy operations."""

    @markers.aws.validated
    def test_put_delivery_destination_policy(
        self, aws_client, account_id, s3_bucket, region_name, snapshot, cleanups
    ):
        """Test putting a policy on a delivery destination."""
        destination_name = f"test-dd-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.regex(s3_bucket, "<bucket>"))

        aws_client.logs.put_delivery_destination(
            name=destination_name,
            deliveryDestinationConfiguration={
                "destinationResourceArn": f"arn:aws:s3:::{s3_bucket}"
            },
        )
        cleanups.append(lambda: aws_client.logs.delete_delivery_destination(name=destination_name))

        policy = get_delivery_destination_policy(region_name, account_id)
        response = aws_client.logs.put_delivery_destination_policy(
            deliveryDestinationName=destination_name,
            deliveryDestinationPolicy=policy,
        )
        snapshot.match("put-delivery-destination-policy", response)

    @markers.aws.validated
    def test_get_delivery_destination_policy(
        self, aws_client, account_id, s3_bucket, region_name, snapshot, cleanups
    ):
        """Test getting a delivery destination policy."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        destination_name = f"test-dd-{short_uid()}"

        aws_client.logs.put_delivery_destination(
            name=destination_name,
            deliveryDestinationConfiguration={
                "destinationResourceArn": f"arn:aws:s3:::{s3_bucket}"
            },
        )
        cleanups.append(lambda: aws_client.logs.delete_delivery_destination(name=destination_name))

        policy = get_delivery_destination_policy(region_name, account_id)
        aws_client.logs.put_delivery_destination_policy(
            deliveryDestinationName=destination_name,
            deliveryDestinationPolicy=policy,
        )

        response = aws_client.logs.get_delivery_destination_policy(
            deliveryDestinationName=destination_name
        )
        snapshot.match("get-delivery-destination-policy", response)

    @markers.aws.validated
    def test_delete_delivery_destination_policy(
        self, aws_client, account_id, s3_bucket, region_name, snapshot, cleanups
    ):
        """Test deleting a delivery destination policy."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        destination_name = f"test-dd-{short_uid()}"

        aws_client.logs.put_delivery_destination(
            name=destination_name,
            deliveryDestinationConfiguration={
                "destinationResourceArn": f"arn:aws:s3:::{s3_bucket}"
            },
        )
        cleanups.append(lambda: aws_client.logs.delete_delivery_destination(name=destination_name))

        policy = get_delivery_destination_policy(region_name, account_id)
        aws_client.logs.put_delivery_destination_policy(
            deliveryDestinationName=destination_name,
            deliveryDestinationPolicy=policy,
        )

        # Delete policy
        aws_client.logs.delete_delivery_destination_policy(deliveryDestinationName=destination_name)

        # Verify deletion
        response = aws_client.logs.get_delivery_destination_policy(
            deliveryDestinationName=destination_name
        )
        assert response["policy"] == {}


class TestDeliverySources:
    """Tests for delivery source operations."""

    @markers.aws.needs_fixing  # requires pro services
    def test_put_delivery_source(self, aws_client, account_id, snapshot, cleanups):
        """Test creating a delivery source."""
        source_name = f"test-ds-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.regex(source_name, "<source-name>"))

        response = aws_client.logs.put_delivery_source(
            name=source_name,
            resourceArn=f"arn:aws:cloudfront::{account_id}:distribution/E1Q5F5862X9VJ5",
            logType="ACCESS_LOGS",
            tags={"key1": "value1"},
        )
        cleanups.append(lambda: aws_client.logs.delete_delivery_source(name=source_name))
        snapshot.match("put-delivery-source", response)

    @markers.aws.validated
    def test_put_delivery_source_invalid_resource(self, aws_client, snapshot):
        """Test creating a delivery source with invalid resource ARN."""
        with pytest.raises(Exception) as ctx:
            aws_client.logs.put_delivery_source(
                name=f"test-ds-{short_uid()}",
                resourceArn="arn:aws:s3:::test-s3-bucket",  # S3 cannot be a source
                logType="ACCESS_LOGS",
            )
        snapshot.match("error-invalid-resource", ctx.value.response)

    @markers.aws.needs_fixing  # requires pro services
    def test_get_delivery_source(self, aws_client, snapshot, cleanups, account_id):
        """Test getting a delivery source."""
        source_name = f"test-ds-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.regex(source_name, "<source-name>"))

        aws_client.logs.put_delivery_source(
            name=source_name,
            resourceArn=f"arn:aws:cloudfront::{account_id}:distribution/E1Q5F5862X9VJ5",
            logType="ACCESS_LOGS",
        )
        cleanups.append(lambda: aws_client.logs.delete_delivery_source(name=source_name))

        response = aws_client.logs.get_delivery_source(name=source_name)
        snapshot.match("get-delivery-source", response)

    @markers.aws.validated
    def test_get_delivery_source_not_found(self, aws_client, snapshot):
        """Test getting a non-existent delivery source."""
        with pytest.raises(Exception) as ctx:
            aws_client.logs.get_delivery_source(name="foobar")
        snapshot.match("error-not-found", ctx.value.response)

    @markers.aws.needs_fixing  # requires pro services
    def test_describe_delivery_sources(self, aws_client, snapshot, cleanups):
        """Test describing delivery sources."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        sources = []

        for i in range(2):
            source_name = f"test-ds-{short_uid()}-{i}"
            aws_client.logs.put_delivery_source(
                name=source_name,
                resourceArn="arn:aws:cloudfront::123456789012:distribution/E19DL18TOXN9JU",
                logType="ACCESS_LOGS",
            )
            sources.append(source_name)
            snapshot.add_transformer(snapshot.transform.regex(source_name, f"<source-{i}>"))
            cleanups.append(lambda sn=source_name: aws_client.logs.delete_delivery_source(name=sn))

        response = aws_client.logs.describe_delivery_sources()
        snapshot.match("describe-delivery-sources", response)
        assert len(response["deliverySources"]) >= 2

    @markers.aws.needs_fixing  # requires pro services
    def test_delete_delivery_source(self, aws_client, snapshot, cleanups):
        """Test deleting a delivery source."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        source_name = f"test-ds-{short_uid()}"

        aws_client.logs.put_delivery_source(
            name=source_name,
            resourceArn="arn:aws:cloudfront::123456789012:distribution/E1Q5F5862X9VJ5",
            logType="ACCESS_LOGS",
        )

        # Delete source
        aws_client.logs.delete_delivery_source(name=source_name)

        # Verify deletion
        with pytest.raises(Exception) as ctx:
            aws_client.logs.get_delivery_source(name=source_name)
        snapshot.match("error-after-delete", ctx.value.response)


class TestDeliveries:
    """Tests for delivery operations (linking sources to destinations)."""

    @markers.aws.needs_fixing  # requires pro services
    def test_create_delivery(
        self, aws_client, account_id, s3_bucket, region_name, snapshot, cleanups
    ):
        """Test creating a delivery."""
        source_name = f"test-ds-{short_uid()}"
        destination_name = f"test-dd-{short_uid()}"

        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.key_value("id"))
        snapshot.add_transformer(snapshot.transform.regex(source_name, "<source>"))
        snapshot.add_transformer(snapshot.transform.regex(destination_name, "<destination>"))

        # Create source
        aws_client.logs.put_delivery_source(
            name=source_name,
            resourceArn=f"arn:aws:cloudfront::{account_id}:distribution/E19DL18TOXN9JU",
            logType="ACCESS_LOGS",
        )
        cleanups.append(lambda: aws_client.logs.delete_delivery_source(name=source_name))

        # Create destination
        aws_client.logs.put_delivery_destination(
            name=destination_name,
            deliveryDestinationConfiguration={
                "destinationResourceArn": f"arn:aws:s3:::{s3_bucket}"
            },
        )
        cleanups.append(lambda: aws_client.logs.delete_delivery_destination(name=destination_name))

        # Create delivery
        destination_arn = (
            f"arn:aws:logs:{region_name}:{account_id}:delivery-destination:{destination_name}"
        )
        response = aws_client.logs.create_delivery(
            deliverySourceName=source_name,
            deliveryDestinationArn=destination_arn,
            recordFields=["date"],
            fieldDelimiter=",",
            s3DeliveryConfiguration={
                "suffixPath": f"AWSLogs/{account_id}/CloudFront/",
                "enableHiveCompatiblePath": True,
            },
            tags={"key1": "value1"},
        )
        delivery_id = response["delivery"]["id"]
        cleanups.append(lambda: aws_client.logs.delete_delivery(id=delivery_id))
        snapshot.match("create-delivery", response)

    @markers.aws.needs_fixing  # requires pro services
    def test_get_delivery(self, aws_client, account_id, s3_bucket, region_name, snapshot, cleanups):
        """Test getting a delivery."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        source_name = f"test-ds-{short_uid()}"
        destination_name = f"test-dd-{short_uid()}"

        snapshot.add_transformer(snapshot.transform.key_value("id"))
        snapshot.add_transformer(snapshot.transform.regex(source_name, "<source>"))
        snapshot.add_transformer(snapshot.transform.regex(destination_name, "<destination>"))

        # Create source and destination
        aws_client.logs.put_delivery_source(
            name=source_name,
            resourceArn=f"arn:aws:cloudfront::{account_id}:distribution/E19DL18TOXN9JU",
            logType="ACCESS_LOGS",
        )
        cleanups.append(lambda: aws_client.logs.delete_delivery_source(name=source_name))

        aws_client.logs.put_delivery_destination(
            name=destination_name,
            deliveryDestinationConfiguration={
                "destinationResourceArn": f"arn:aws:s3:::{s3_bucket}"
            },
        )
        cleanups.append(lambda: aws_client.logs.delete_delivery_destination(name=destination_name))

        # Create delivery
        destination_arn = (
            f"arn:aws:logs:{region_name}:{account_id}:delivery-destination:{destination_name}"
        )
        create_response = aws_client.logs.create_delivery(
            deliverySourceName=source_name,
            deliveryDestinationArn=destination_arn,
        )
        delivery_id = create_response["delivery"]["id"]
        cleanups.append(lambda: aws_client.logs.delete_delivery(id=delivery_id))

        # Get delivery
        response = aws_client.logs.get_delivery(id=delivery_id)
        snapshot.match("get-delivery", response)

    @markers.aws.needs_fixing  # requires pro services
    def test_describe_deliveries(
        self, aws_client, account_id, s3_bucket, region_name, snapshot, cleanups
    ):
        """Test describing deliveries."""
        source_name = f"test-ds-{short_uid()}"
        destination_name = f"test-dd-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.key_value("id"))
        snapshot.add_transformer(snapshot.transform.regex(source_name, "<source>"))
        snapshot.add_transformer(snapshot.transform.regex(destination_name, "<destination>"))

        # Create source
        aws_client.logs.put_delivery_source(
            name=source_name,
            resourceArn=f"arn:aws:cloudfront::{account_id}:distribution/E19DL18TOXN9JU",
            logType="ACCESS_LOGS",
        )
        cleanups.append(lambda: aws_client.logs.delete_delivery_source(name=source_name))

        # Create two destinations and deliveries
        aws_client.logs.put_delivery_destination(
            name=destination_name,
            deliveryDestinationConfiguration={
                "destinationResourceArn": f"arn:aws:s3:::{s3_bucket}"
            },
        )
        cleanups.append(
            lambda dn=destination_name: aws_client.logs.delete_delivery_destination(name=dn)
        )

        destination_arn = (
            f"arn:aws:logs:{region_name}:{account_id}:delivery-destination:{destination_name}"
        )
        create_response = aws_client.logs.create_delivery(
            deliverySourceName=source_name,
            deliveryDestinationArn=destination_arn,
        )
        delivery_id = create_response["delivery"]["id"]
        cleanups.append(lambda: aws_client.logs.delete_delivery(id=delivery_id))

        response = aws_client.logs.describe_deliveries()
        descriptions = [desc for desc in response["deliveries"] if desc["id"] == delivery_id]
        snapshot.match("describe-deliveries", descriptions)

    @markers.aws.needs_fixing  # requires pro services
    def test_delete_delivery(
        self, aws_client, account_id, s3_bucket, region_name, snapshot, cleanups
    ):
        """Test deleting a delivery."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        source_name = f"test-ds-{short_uid()}"
        destination_name = f"test-dd-{short_uid()}"

        # Create source and destination
        aws_client.logs.put_delivery_source(
            name=source_name,
            resourceArn=f"arn:aws:cloudfront::{account_id}:distribution/E19DL18TOXN9JU",
            logType="ACCESS_LOGS",
        )
        cleanups.append(lambda: aws_client.logs.delete_delivery_source(name=source_name))

        aws_client.logs.put_delivery_destination(
            name=destination_name,
            deliveryDestinationConfiguration={
                "destinationResourceArn": f"arn:aws:s3:::{s3_bucket}"
            },
        )
        cleanups.append(lambda: aws_client.logs.delete_delivery_destination(name=destination_name))

        # Create delivery
        destination_arn = (
            f"arn:aws:logs:{region_name}:{account_id}:delivery-destination:{destination_name}"
        )
        create_response = aws_client.logs.create_delivery(
            deliverySourceName=source_name,
            deliveryDestinationArn=destination_arn,
        )
        delivery_id = create_response["delivery"]["id"]

        # Delete delivery
        aws_client.logs.delete_delivery(id=delivery_id)

        # Verify deletion
        with pytest.raises(Exception) as ctx:
            aws_client.logs.get_delivery(id=delivery_id)
        snapshot.match("error-after-delete", ctx.value.response)
