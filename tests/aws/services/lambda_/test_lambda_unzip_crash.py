import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from localstack.services.lambda_.invocation.lambda_models import S3Code
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestLambdaUnzipCrash:
    @markers.aws.only_localstack
    def test_unzip_crash_leaves_no_corrupted_files(self, aws_client, tmp_path, monkeypatch):
        """
        Integration test to test fix for issue https://github.com/localstack/localstack/issues/13555
        Simulates what happens when we crash during Lambda code unzipping.
        Makes sure no corrupted file is left.
        """

        unzip_call_count = 0
        function_id = f"test-unzip-crash-{short_uid()}"

        def crashing_unzip(zip_file, target_dir):
            """Unzip that crashes after writing partial content"""
            nonlocal unzip_call_count
            unzip_call_count += 1

            target_path = Path(target_dir)
            target_path.mkdir(parents=True, exist_ok=True)
            (target_path / "handler.py").write_text("# CORRUPTED - partial unpack\n")

            raise RuntimeError("Simulated crash during unzip")

        s3_code = S3Code(
            id=function_id,
            account_id="000000000000",
            s3_bucket="test-bucket",
            s3_key="test.zip",
            s3_object_version=None,
            code_sha256="abc123",
            code_size=1024,
        )

        def mock_download(self, target_file):
            target_file.write(b"fake-zip")
            target_file.flush()

        # Patch unzip and download
        with patch(
            "localstack.services.lambda_.invocation.lambda_models.unzip", side_effect=crashing_unzip
        ):
            with patch.object(S3Code, "_download_archive_to_file", mock_download):
                # This will trigger the unzip operation (which will crash)
                try:
                    s3_code.prepare_for_execution()
                except RuntimeError:
                    pass

        # Check what's on disk
        target_code_dir = (
            Path(tempfile.gettempdir()) / "lambda" / "test-bucket" / function_id / "code"
        )

        if target_code_dir.exists():
            handler_file = target_code_dir / "handler.py"
            if handler_file.exists():
                content = handler_file.read_text()
                if "CORRUPTED" in content:
                    pytest.fail(
                        f"Crash during unzip left corrupted files on disk at {target_code_dir}!"
                    )

        assert unzip_call_count >= 1, "Unzip should have been called"
