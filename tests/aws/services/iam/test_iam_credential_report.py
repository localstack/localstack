"""
Tests for IAM Credential Report operations.

Migrated from moto: tests/test_iam/test_iam.py
- test_generate_credential_report()
- test_get_credential_report()
- test_get_credential_report_content()

Note: Credential reports can only be generated once every 4 hours in AWS.
These tests use a class-scoped fixture to generate the report once and share it.
"""

import csv
import io
import logging

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)


@pytest.fixture(scope="class")
def credential_report_user(aws_client):
    """Create a user that will appear in the credential report."""
    user_name = f"cred-report-user-{short_uid()}"
    aws_client.iam.create_user(UserName=user_name)
    yield user_name
    try:
        aws_client.iam.delete_user(UserName=user_name)
    except Exception:
        LOG.debug("Could not delete user '%s' during cleanup", user_name)


@pytest.fixture(scope="class")
def credential_report(aws_client, credential_report_user):
    """Generate credential report once for all tests in the class.

    This fixture generates the report and returns both the generation response
    and the report content. Since reports can only be generated every 4 hours,
    we generate once and share across all tests.
    """
    # Generate the report - keep calling until complete
    generate_response = aws_client.iam.generate_credential_report()
    while generate_response["State"] != "COMPLETE":
        generate_response = aws_client.iam.generate_credential_report()

    # Get the report
    report_response = aws_client.iam.get_credential_report()
    report_content = report_response["Content"].decode("utf-8")

    return {
        "generate_response": generate_response,
        "report_response": report_response,
        "report_content": report_content,
        "user_name": credential_report_user,
    }


class TestIAMCredentialReport:
    """Tests for IAM credential report generation and retrieval.

    All tests share a single credential report generated via the class-scoped
    credential_report fixture, since AWS limits report generation to once per 4 hours.
    """

    @markers.aws.validated
    def test_generate_credential_report_complete(self, snapshot, credential_report):
        """Test that credential report generation completes successfully."""
        snapshot.add_transformer(snapshot.transform.iam_api())

        # The fixture already generated the report - verify it completed
        snapshot.match("generate-complete", credential_report["generate_response"])

    @markers.aws.validated
    def test_get_credential_report_metadata(self, snapshot, credential_report):
        """Test credential report metadata (format, generated time)."""
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GeneratedTime"))

        # Extract metadata from the response (excluding Content which is binary)
        metadata = {
            "ReportFormat": credential_report["report_response"].get("ReportFormat"),
            "GeneratedTime": credential_report["report_response"].get("GeneratedTime"),
        }
        snapshot.match("report-metadata", metadata)

    @markers.aws.validated
    def test_credential_report_contains_user(self, snapshot, credential_report):
        """Test that the credential report contains the test user."""
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(
            snapshot.transform.regex(credential_report["user_name"], "<user-name>")
        )

        user_found = credential_report["user_name"] in credential_report["report_content"]
        snapshot.match("user-in-report", {"user_found": user_found})

    @markers.aws.validated
    def test_credential_report_csv_header_format(self, snapshot, credential_report):
        """Test that the credential report CSV has the expected header format."""
        snapshot.add_transformer(snapshot.transform.iam_api())

        # Parse CSV and get header
        reader = csv.reader(io.StringIO(credential_report["report_content"]))
        header = next(reader)
        actual_header = ",".join(header)

        snapshot.match("csv-header", {"header": actual_header})

    @markers.aws.validated
    def test_credential_report_user_row_structure(self, snapshot, credential_report):
        """Test that the credential report contains correct user row structure."""
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(
            snapshot.transform.regex(credential_report["user_name"], "<user-name>")
        )

        # Parse CSV and find our user
        reader = csv.DictReader(io.StringIO(credential_report["report_content"]))
        user_row = None
        for row in reader:
            if row["user"] == credential_report["user_name"]:
                user_row = dict(row)
                break

        assert user_row
        snapshot.match("user-row-deterministic", user_row)
