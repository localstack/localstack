import csv
import io
import logging

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

LOG = logging.getLogger(__name__)

# TODO remove once implemented
pytestmark = pytest.mark.skip


class TestIAMCredentialReport:
    """Tests for IAM credential report generation and retrieval.
    Generating a new credential report is hard as it is only possible every 4 hours
    """

    @markers.aws.validated
    def test_get_credential_report_before_generated(self, aws_client, create_user, snapshot):
        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_credential_report()
        snapshot.match("get-credential-report-without-generate-error", exc.value.response)

    @markers.aws.validated
    def test_credential_report(self, aws_client, create_user, snapshot):
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("AccessKeyId"))
        snapshot.add_transformer(snapshot.transform.key_value("SecretAccessKey"))

        user_name = f"test-user-{short_uid()}"
        user_response = create_user(UserName=user_name)
        snapshot.match("create-user", user_response)

        create_login_profile_response = aws_client.iam.create_login_profile(
            UserName=user_name, Password="TestPassword123!", PasswordResetRequired=False
        )
        snapshot.match("create-login-profile", create_login_profile_response)
        create_access_key_response = aws_client.iam.create_access_key(UserName=user_name)
        snapshot.match("create-access-key-1", create_access_key_response)
        aws_client.iam.update_access_key(
            UserName=user_name,
            AccessKeyId=create_access_key_response["AccessKey"]["AccessKeyId"],
            Status="Inactive",
        )
        create_access_key_response = aws_client.iam.create_access_key(UserName=user_name)
        snapshot.match("create-access-key-2", create_access_key_response)

        initial_generate_response = aws_client.iam.generate_credential_report()
        snapshot.match("initial-generate-response", initial_generate_response)

        def _generate_report():
            response = aws_client.iam.generate_credential_report()
            assert response["State"] == "COMPLETE"
            return response

        generate_response = retry(_generate_report, retries=120, sleep=5)
        snapshot.match("generate-completed-response", generate_response)

        # Get the report
        report_response = aws_client.iam.get_credential_report()
        report_content = report_response["Content"].decode("utf-8")

        reader = csv.DictReader(io.StringIO(report_content))
        users = []
        for entry in reader:
            users.append(entry)

        users_filtered = [user for user in users if user["user"] == user_name]
        snapshot.match(
            "credentials-report", {"field_names": reader.fieldnames, "users": users_filtered}
        )
