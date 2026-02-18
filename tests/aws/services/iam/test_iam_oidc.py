"""
Tests for IAM OpenID Connect (OIDC) Provider operations.

Migrated from moto tests: moto-repo/tests/test_iam/test_iam_oidc.py
"""

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.common import short_uid


class TestOIDCProviderCreate:
    """Tests for creating OpenID Connect providers."""

    @markers.aws.validated
    def test_create_open_id_connect_provider(self, aws_client, snapshot, cleanups):
        """Test creating OIDC providers with different URL formats."""
        snapshot.add_transformer(snapshot.transform.key_value("OpenIDConnectProviderArn"))
        uid = short_uid()

        # Test basic creation with HTTPS URL
        url1 = f"https://oidc-basic-{uid}.example.com"
        response = aws_client.iam.create_open_id_connect_provider(
            Url=url1,
            ThumbprintList=["a" * 40],
        )
        arn1 = response["OpenIDConnectProviderArn"]
        cleanups.append(
            lambda a=arn1: aws_client.iam.delete_open_id_connect_provider(
                OpenIDConnectProviderArn=a
            )
        )
        assert f"oidc-basic-{uid}.example.com" in arn1
        snapshot.match("create-https", response)

        # Test creation with thumbprint and client ID
        url2 = f"https://oidc-client-{uid}.example.com"
        response = aws_client.iam.create_open_id_connect_provider(
            Url=url2, ThumbprintList=["b" * 40], ClientIDList=["my-client-id"]
        )
        arn2 = response["OpenIDConnectProviderArn"]
        cleanups.append(
            lambda a=arn2: aws_client.iam.delete_open_id_connect_provider(
                OpenIDConnectProviderArn=a
            )
        )
        snapshot.match("create-with-client", response)

        # Test creation with URL path
        url3 = f"https://oidc-path-{uid}.example.com/oidc"
        response = aws_client.iam.create_open_id_connect_provider(
            Url=url3, ThumbprintList=["a" * 40]
        )
        arn3 = response["OpenIDConnectProviderArn"]
        cleanups.append(
            lambda a=arn3: aws_client.iam.delete_open_id_connect_provider(
                OpenIDConnectProviderArn=a
            )
        )
        snapshot.match("create-with-path", response)


class TestOIDCProviderCreateErrors:
    """Tests for error handling when creating OpenID Connect providers."""

    @markers.aws.validated
    def test_create_open_id_connect_provider_invalid_url(self, aws_client, snapshot):
        """Test error when creating OIDC provider with invalid URL."""
        with pytest.raises(ClientError) as exc:
            aws_client.iam.create_open_id_connect_provider(
                Url="example.org", ThumbprintList=["a" * 40]
            )
        snapshot.match("invalid-url", exc.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_create_open_id_connect_provider_duplicate_error(self, aws_client, snapshot, cleanups):
        """Test error when creating duplicate OIDC provider."""
        url = f"https://oidc-dup-{short_uid()}.example.com"
        response = aws_client.iam.create_open_id_connect_provider(
            Url=url, ThumbprintList=["a" * 40]
        )
        arn = response["OpenIDConnectProviderArn"]
        cleanups.append(
            lambda: aws_client.iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        )

        with pytest.raises(ClientError) as exc:
            aws_client.iam.create_open_id_connect_provider(Url=url, ThumbprintList=["a" * 40])
        snapshot.match("duplicate-error", exc.value.response)

    @markers.aws.validated
    def test_create_open_id_connect_provider_too_many_thumbprints(self, aws_client, snapshot):
        """Test error when creating OIDC provider with too many thumbprints."""
        with pytest.raises(ClientError) as exc:
            aws_client.iam.create_open_id_connect_provider(
                Url=f"https://oidc-thumbs-{short_uid()}.example.com",
                ThumbprintList=[
                    "a" * 40,
                    "b" * 40,
                    "c" * 40,
                    "d" * 40,
                    "e" * 40,
                    "f" * 40,
                ],
            )
        snapshot.match("too-many-thumbprints", exc.value.response)

    @markers.aws.validated
    def test_create_open_id_connect_provider_quota_error(self, aws_client, snapshot):
        """Test error when creating OIDC provider with too many client IDs."""
        too_many_client_ids = [f"{i}" for i in range(101)]
        with pytest.raises(ClientError) as exc:
            aws_client.iam.create_open_id_connect_provider(
                Url=f"https://oidc-clients-{short_uid()}.example.com",
                ThumbprintList=["a" * 40],
                ClientIDList=too_many_client_ids,
            )
        snapshot.match("quota-error", exc.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_create_open_id_connect_provider_validation_errors(self, aws_client, snapshot):
        """Test multiple validation errors when creating OIDC provider."""
        too_long_url = "b" * 256
        too_long_thumbprint = "b" * 41
        too_long_client_id = "b" * 256

        with pytest.raises(ClientError) as exc:
            aws_client.iam.create_open_id_connect_provider(
                Url=too_long_url,
                ThumbprintList=[too_long_thumbprint],
                ClientIDList=[too_long_client_id],
            )
        snapshot.match("multiple-validation-errors", exc.value.response)


class TestOIDCProviderOperations:
    """Tests for OIDC provider CRUD operations."""

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Tags"])
    def test_get_open_id_connect_provider(self, aws_client, snapshot, cleanups):
        """Test retrieving an OIDC provider."""
        snapshot.add_transformer(snapshot.transform.key_value("Url"))

        url = f"https://oidc-get-{short_uid()}.example.com"
        response = aws_client.iam.create_open_id_connect_provider(
            Url=url,
            ThumbprintList=["b" * 40],
            ClientIDList=["client-id-1"],
        )
        arn = response["OpenIDConnectProviderArn"]
        cleanups.append(
            lambda: aws_client.iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        )

        get_response = aws_client.iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        snapshot.match("get-response", get_response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_get_open_id_connect_provider_not_found(
        self, aws_client, account_id, snapshot, partition
    ):
        """Test error when getting a non-existent OIDC provider."""
        fake_arn = f"arn:{partition}:iam::{account_id}:oidc-provider/non-existent.example.com"

        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_open_id_connect_provider(OpenIDConnectProviderArn=fake_arn)
        snapshot.match("not-found-error", exc.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Tags"])
    def test_update_open_id_connect_provider_thumbprint(self, aws_client, snapshot, cleanups):
        """Test updating an OIDC provider's thumbprint list."""
        snapshot.add_transformer(snapshot.transform.key_value("Url"))

        url = f"https://oidc-update-{short_uid()}.example.com"
        response = aws_client.iam.create_open_id_connect_provider(
            Url=url, ThumbprintList=["b" * 40]
        )
        arn = response["OpenIDConnectProviderArn"]
        cleanups.append(
            lambda: aws_client.iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        )

        # Update thumbprint list
        aws_client.iam.update_open_id_connect_provider_thumbprint(
            OpenIDConnectProviderArn=arn, ThumbprintList=["c" * 40, "d" * 40]
        )

        # Verify the update
        get_response = aws_client.iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        snapshot.match("after-update", get_response)

    @markers.aws.validated
    @pytest.mark.skip("Idempotency is implemented but it shouldn't")
    def test_delete_open_id_connect_provider(self, aws_client, snapshot):
        """Test deleting an OIDC provider."""
        url = f"https://oidc-delete-{short_uid()}.example.com"
        response = aws_client.iam.create_open_id_connect_provider(
            Url=url, ThumbprintList=["a" * 40]
        )
        arn = response["OpenIDConnectProviderArn"]

        # Delete the provider
        delete_response = aws_client.iam.delete_open_id_connect_provider(
            OpenIDConnectProviderArn=arn
        )
        snapshot.match("delete-response", delete_response)

        # Verify it's gone by trying to get it
        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        assert "NoSuchEntity" in str(exc.value) or "not found" in str(exc.value).lower()

        # Verify operation is not idempotent
        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        assert "NoSuchEntity" in str(exc.value) or "not found" in str(exc.value).lower()


class TestOIDCProviderList:
    """Tests for listing OpenID Connect providers."""

    @markers.aws.validated
    def test_list_open_id_connect_providers(self, aws_client, snapshot, cleanups):
        """Test listing OIDC providers."""
        snapshot.add_transformer(snapshot.transform.key_value("Arn"))

        # Create multiple providers
        uid = short_uid()
        arns = []
        for i in range(3):
            domain = f"oidc-list-{i}-{uid}.example.com"
            response = aws_client.iam.create_open_id_connect_provider(
                Url=f"https://{domain}", ThumbprintList=["a" * 40]
            )
            arn = response["OpenIDConnectProviderArn"]
            arns.append(arn)
            cleanups.append(
                lambda a=arn: aws_client.iam.delete_open_id_connect_provider(
                    OpenIDConnectProviderArn=a
                )
            )
            snapshot.add_transformer(snapshot.transform.regex(domain, f"<domain-{i}>"))

        # List providers
        response = aws_client.iam.list_open_id_connect_providers()

        # Verify our providers are in the list
        listed_arns = [p["Arn"] for p in response["OpenIDConnectProviderList"]]
        for arn in arns:
            assert arn in listed_arns
        snapshot.match("list-response", listed_arns)


class TestOIDCProviderTags:
    """Tests for OIDC provider tagging operations."""

    @markers.aws.validated
    def test_tag_open_id_connect_provider(self, aws_client, snapshot, cleanups):
        """Test adding tags to an OIDC provider."""
        url = f"https://oidc-tag-{short_uid()}.example.com"
        response = aws_client.iam.create_open_id_connect_provider(
            Url=url, ThumbprintList=["a" * 40]
        )
        arn = response["OpenIDConnectProviderArn"]
        cleanups.append(
            lambda: aws_client.iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        )

        # Add tags
        aws_client.iam.tag_open_id_connect_provider(
            OpenIDConnectProviderArn=arn,
            Tags=[{"Key": "k1", "Value": "v1"}, {"Key": "k2", "Value": "v2"}],
        )

        # Verify tags were added
        get_response = aws_client.iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        snapshot.match("after-tagging", {"Tags": get_response.get("Tags", [])})

    @markers.aws.validated
    def test_untag_open_id_connect_provider(self, aws_client, snapshot, cleanups):
        """Test removing tags from an OIDC provider."""
        url = f"https://oidc-untag-{short_uid()}.example.com"
        response = aws_client.iam.create_open_id_connect_provider(
            Url=url, ThumbprintList=["a" * 40]
        )
        arn = response["OpenIDConnectProviderArn"]
        cleanups.append(
            lambda: aws_client.iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        )

        # Add tags
        aws_client.iam.tag_open_id_connect_provider(
            OpenIDConnectProviderArn=arn,
            Tags=[{"Key": "k1", "Value": "v1"}, {"Key": "k2", "Value": "v2"}],
        )

        # Remove one tag
        aws_client.iam.untag_open_id_connect_provider(OpenIDConnectProviderArn=arn, TagKeys=["k2"])

        # Verify tag was removed
        get_response = aws_client.iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        snapshot.match("after-untagging", {"Tags": get_response.get("Tags", [])})

        assert len(get_response["Tags"]) == 1
        assert {"Key": "k1", "Value": "v1"} in get_response["Tags"]

    @markers.aws.validated
    def test_list_open_id_connect_provider_tags(self, aws_client, snapshot, cleanups):
        """Test listing tags for an OIDC provider."""
        url = f"https://oidc-listtags-{short_uid()}.example.com"
        response = aws_client.iam.create_open_id_connect_provider(
            Url=url,
            ThumbprintList=["a" * 40],
            Tags=[{"Key": "k1", "Value": "v1"}, {"Key": "k2", "Value": "v2"}],
        )
        arn = response["OpenIDConnectProviderArn"]
        cleanups.append(
            lambda: aws_client.iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        )

        # List tags
        list_response = aws_client.iam.list_open_id_connect_provider_tags(
            OpenIDConnectProviderArn=arn
        )
        snapshot.match("list-tags-response", list_response)

    @markers.aws.validated
    def test_list_open_id_connect_provider_tags_max_items(self, aws_client, snapshot, cleanups):
        """Test MaxItems parameter when listing tags for an OIDC provider."""
        # Create provider with 10 tags
        tags = [{"Key": f"k{idx:02d}", "Value": f"v{idx}"} for idx in range(10)]
        url = f"https://oidc-tagsmax-{short_uid()}.example.com"
        response = aws_client.iam.create_open_id_connect_provider(
            Url=url,
            ThumbprintList=["a" * 40],
            Tags=tags,
        )
        arn = response["OpenIDConnectProviderArn"]
        cleanups.append(
            lambda: aws_client.iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        )

        # First page with MaxItems=4
        response = aws_client.iam.list_open_id_connect_provider_tags(
            OpenIDConnectProviderArn=arn, MaxItems=4
        )
        assert len(response["Tags"]) == 4

        # Second page with MaxItems=4
        response = aws_client.iam.list_open_id_connect_provider_tags(
            OpenIDConnectProviderArn=arn, Marker=response["Marker"], MaxItems=4
        )
        assert len(response["Tags"]) == 4

        # Third and final page
        response = aws_client.iam.list_open_id_connect_provider_tags(
            OpenIDConnectProviderArn=arn, Marker=response["Marker"]
        )
        snapshot.match(
            "final-page", {"tag_count": len(response["Tags"]), "has_marker": "Marker" in response}
        )
        assert len(response["Tags"]) == 2

    @markers.aws.validated
    @pytest.mark.skip("tag limit should be 50")
    def test_open_id_connect_provider_tags_limit(self, aws_client, snapshot, cleanups):
        """Test the max amount of tags an OIDC provider can have."""
        tags = [{"Key": f"k{idx:02d}", "Value": f"v{idx}"} for idx in range(50)]
        url = f"https://oidc-tagsmax-{short_uid()}.example.com"
        arn = aws_client.iam.create_open_id_connect_provider(
            Url=url,
            ThumbprintList=["a" * 40],
            Tags=tags,
        )["OpenIDConnectProviderArn"]
        cleanups.append(
            lambda: aws_client.iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        )

        # Add one more
        with pytest.raises(ClientError) as ctx:
            aws_client.iam.tag_open_id_connect_provider(
                OpenIDConnectProviderArn=arn,
                Tags=[
                    {"Key": "string", "Value": "string"},
                ],
            )
        snapshot.match("tags-limit-error", ctx.value.response)
