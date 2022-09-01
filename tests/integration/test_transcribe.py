import os

import pytest
from botocore.exceptions import ClientError

from localstack.aws.api.transcribe import BadRequestException, NotFoundException
from localstack.utils.platform import get_arch
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition

BASEDIR = os.path.abspath(os.path.dirname(__file__))


@pytest.fixture(autouse=True)
def transcribe_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.transcribe_api())


@pytest.mark.skipif(
    "arm" in get_arch(),
    reason="Vosk transcription library has issues running on Circle CI arm64 executors.",
)
class TestTranscribe:
    @pytest.mark.skip_offline
    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..TranscriptionJob..MediaSampleRateHertz",
            "$..TranscriptionJob..Settings",
            "$..Error..Code",
        ]
    )
    def test_transcribe_happy_path(self, transcribe_client, transcribe_create_job, snapshot):
        file_path = os.path.join(BASEDIR, "files/en-gb.wav")
        job_name = transcribe_create_job(audio_file=file_path)
        transcribe_client.get_transcription_job(TranscriptionJobName=job_name)

        def is_transcription_done():
            transcription_status = transcribe_client.get_transcription_job(
                TranscriptionJobName=job_name
            )
            return transcription_status["TranscriptionJob"]["TranscriptionJobStatus"] == "COMPLETED"

        # empirically it takes around
        # <5sec for a vosk transcription
        # ~100sec for an AWS transcription -> adjust timeout accordingly
        assert poll_condition(
            is_transcription_done, timeout=10
        ), f"could not finish transcription job: {job_name} in time"

        job = transcribe_client.get_transcription_job(TranscriptionJobName=job_name)
        snapshot.match("TranscriptionJob", job)

        # delete the job again
        transcribe_client.delete_transcription_job(TranscriptionJobName=job_name)

        # check if job is gone
        with pytest.raises((ClientError, NotFoundException)) as e_info:
            transcribe_client.get_transcription_job(TranscriptionJobName=job_name)

        snapshot.match("GetError", e_info.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=["$..TranscriptionJob..Settings", "$..TranscriptionJob..Transcript", "$..Error..Code"]
    )
    def test_get_transcription_job(self, transcribe_client, transcribe_create_job, snapshot):
        file_path = os.path.join(BASEDIR, "files/en-gb.wav")
        job_name = transcribe_create_job(audio_file=file_path)

        job = transcribe_client.get_transcription_job(TranscriptionJobName=job_name)

        snapshot.match("GetJob", job)

        with pytest.raises((ClientError, NotFoundException)) as e_info:
            transcribe_client.get_transcription_job(TranscriptionJobName="non-existent")

        snapshot.match("GetError", e_info.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=["$..NextToken", "$..TranscriptionJobSummaries..OutputLocationType"]
    )
    def test_list_transcription_jobs(self, transcribe_client, transcribe_create_job, snapshot):
        file_path = os.path.join(BASEDIR, "files/en-gb.wav")
        transcribe_create_job(audio_file=file_path)

        jobs = transcribe_client.list_transcription_jobs()

        # there are potentially multiple transcription jobs on AWS - ordered by creation date
        # we only care about the newest one that we just created
        jobs["TranscriptionJobSummaries"] = jobs["TranscriptionJobSummaries"][0]

        snapshot.match("ListJobs", jobs)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..Error..Code"])
    def test_failing_deletion(self, transcribe_client, snapshot):
        # successful deletion is tested in the happy path test
        # this tests a failed deletion
        with pytest.raises((ClientError, NotFoundException)) as e_info:
            transcribe_client.delete_transcription_job(TranscriptionJobName="non-existent")

        snapshot.match("MissingLanguageCode", e_info.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=["$..MissingLanguageCode..Message", "$..MalformedLanguageCode..Message"]
    )
    def test_failing_start_transcription_job(
        self, s3_client, s3_bucket, transcribe_client, snapshot
    ):
        transcription_job = f"test-transcribe-{short_uid()}"
        test_key = "test-clip.wav"
        file_path = os.path.join(BASEDIR, "files/en-gb.wav")

        with open(file_path, "rb") as f:
            s3_client.upload_fileobj(f, s3_bucket, test_key)

        # missing language code
        with pytest.raises((ClientError, BadRequestException)) as e_info:
            transcribe_client.start_transcription_job(
                TranscriptionJobName=transcription_job,
                Media={"MediaFileUri": f"s3://{s3_bucket}/{test_key}"},
            )

        snapshot.match("MissingLanguageCode", e_info.value.response)

        # malformed language code
        language_code = "non-existent"
        with pytest.raises((ClientError, BadRequestException)) as e_info:
            transcribe_client.start_transcription_job(
                TranscriptionJobName=transcription_job,
                LanguageCode=language_code,
                Media={"MediaFileUri": f"s3://{s3_bucket}/{test_key}"},
            )
        snapshot.match("MalformedLanguageCode", e_info.value.response)
