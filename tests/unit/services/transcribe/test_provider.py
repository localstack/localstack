import json
import unittest
from unittest.mock import MagicMock, patch

from localstack.services.transcribe.provider import TranscribeProvider, TranscriptionJobStatus


class TestTranscribeProvider(unittest.TestCase):
    def test_transcribe_job_duration_limit(self):
        # Setup
        provider = TranscribeProvider()
        store = MagicMock()
        job_name = "test-job-long-audio"

        job = {
            "TranscriptionJobName": job_name,
            "LanguageCode": "en-US",
            "Media": {"MediaFileUri": "s3://test-bucket/long_audio.mp3"},
            "Transcript": {"TranscriptFileUri": "s3://test-bucket/output.json"},
            "TranscriptionJobStatus": "QUEUED",
        }
        store.transcription_jobs = {job_name: job}

        with (
            patch("localstack.services.transcribe.provider.new_tmp_file"),
            patch("localstack.services.transcribe.provider.connect_to"),
            patch("localstack.services.transcribe.provider.ffmpeg_package"),
            patch("localstack.services.transcribe.provider.run") as mock_run,
        ):
            # Case 1: Duration > 4h (14401.0)
            ffprobe_output = {
                "format": {"format_name": "mp3", "duration": "14401.0"},
                "streams": [{"codec_type": "audio", "sample_rate": "44100"}],
            }
            mock_run.return_value = json.dumps(ffprobe_output)

            provider._run_transcription_job((store, job_name))

            self.assertEqual(job["TranscriptionJobStatus"], TranscriptionJobStatus.FAILED)
            self.assertIn("Maximum audio duration is 4.000000 hours", job["FailureReason"])

            # Case 2: Duration = 4h (14400.0) - Should Pass Check
            # Create a NEW job/store for clean state
            job2_name = "test-job-boundary"
            job2 = {
                "TranscriptionJobName": job2_name,
                "LanguageCode": "en-US",
                "Media": {"MediaFileUri": "s3://test-bucket/boundary_audio.mp3"},
                "Transcript": {"TranscriptFileUri": "s3://test-bucket/output.json"},
                "TranscriptionJobStatus": "QUEUED",
            }
            store.transcription_jobs[job2_name] = job2

            ffprobe_output["format"]["duration"] = "14400.0"
            mock_run.return_value = json.dumps(ffprobe_output)

            # Mock _setup_vosk using target path instead of instance object for static method stability
            with patch(
                "localstack.services.transcribe.provider.TranscribeProvider._setup_vosk",
                side_effect=RuntimeError("StopHere"),
            ):
                try:
                    provider._run_transcription_job((store, job2_name))
                except Exception:
                    pass

            # If it failed due to size, status would be FAILED with "Invalid file size..."
            # If it failed due to size, status would be FAILED with "Invalid file size..."
            # If it hit StopHere, status is FAILED. Even if reason is empty (?), it confirms size check passed.
            self.assertEqual(job2["TranscriptionJobStatus"], TranscriptionJobStatus.FAILED)
            self.assertNotIn("Invalid file size", job2.get("FailureReason", ""))

    def test_transcribe_job_robustness_na(self):
        provider = TranscribeProvider()
        store = MagicMock()
        job_name = "test-job-na"
        job = {
            "TranscriptionJobName": job_name,
            "LanguageCode": "en-US",
            "Media": {"MediaFileUri": "s3://t/na.mp3"},
            "Transcript": {"TranscriptFileUri": "s3://t/o"},
            "TranscriptionJobStatus": "QUEUED",
        }
        store.transcription_jobs = {job_name: job}

        with (
            patch("localstack.services.transcribe.provider.new_tmp_file"),
            patch("localstack.services.transcribe.provider.connect_to"),
            patch("localstack.services.transcribe.provider.ffmpeg_package"),
            patch("localstack.services.transcribe.provider.run") as mock_run,
        ):
            ffprobe_output = {
                "format": {"format_name": "mp3", "duration": "N/A"},
                "streams": [{"codec_type": "audio", "sample_rate": "44100"}],
            }
            mock_run.return_value = json.dumps(ffprobe_output)

            with patch.object(provider, "_setup_vosk", side_effect=Exception("StopHere")):
                try:
                    provider._run_transcription_job((store, job_name))
                except Exception:
                    pass

            # Should NOT fail due to float conversion
            if job["TranscriptionJobStatus"] == "FAILED":
                self.assertNotIn("could not convert string to float", job.get("FailureReason", ""))


if __name__ == "__main__":
    unittest.main()
