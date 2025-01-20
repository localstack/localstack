import logging
import os
import threading
import time
from urllib.parse import urlparse

import pytest
from botocore.exceptions import ClientError

from localstack.aws.api.transcribe import BadRequestException, ConflictException, NotFoundException
from localstack.aws.connect import ServiceLevelClientFactory
from localstack.packages.ffmpeg import ffmpeg_package
from localstack.services.transcribe.packages import vosk_package
from localstack.services.transcribe.provider import LANGUAGE_MODELS, TranscribeProvider
from localstack.testing.pytest import markers
from localstack.utils.files import new_tmp_file
from localstack.utils.strings import short_uid, to_str
from localstack.utils.sync import poll_condition, retry
from localstack.utils.threads import start_worker_thread

BASEDIR = os.path.abspath(os.path.dirname(__file__))

LOG = logging.getLogger(__name__)

# Lock and event to ensure that the installation is executed before the tests
vosk_installed = threading.Event()
ffmpeg_installed = threading.Event()
installation_errored = threading.Event()

INSTALLATION_TIMEOUT = 5 * 60
PRE_DOWNLOAD_LANGUAGE_CODE_MODELS = ["en-GB"]


def install_async():
    """
    Installs the default ffmpeg and vosk versions in a worker thread.
    """
    if vosk_installed.is_set() and ffmpeg_installed.is_set():
        return

    def install_vosk(*args):
        if vosk_installed.is_set():
            return
        try:
            LOG.info("installing Vosk default version")
            vosk_package.install()
            LOG.info("done installing Vosk default version")
            LOG.info("downloading Vosk models used in test: %s", PRE_DOWNLOAD_LANGUAGE_CODE_MODELS)
            for language_code in PRE_DOWNLOAD_LANGUAGE_CODE_MODELS:
                model_name = LANGUAGE_MODELS[language_code]
                # downloading the model takes quite a while sometimes
                TranscribeProvider.download_model(model_name)
                LOG.info(
                    "done downloading Vosk model '%s' for language code '%s'",
                    model_name,
                    language_code,
                )
            LOG.info("done downloading all Vosk models used in test")
        except Exception:
            LOG.exception("Error during installation of Vosk dependencies")
            installation_errored.set()
            # we also set the other event to quickly stop the polling
            ffmpeg_installed.set()
        finally:
            vosk_installed.set()

    def install_ffmpeg(*args):
        if ffmpeg_installed.is_set():
            return
        try:
            LOG.info("installing ffmpeg default version")
            ffmpeg_package.install()
            LOG.info("done ffmpeg default version")
        except Exception:
            LOG.exception("Error during installation of Vosk dependencies")
            installation_errored.set()
            # we also set the other event to quickly stop the polling
            vosk_installed.set()
        finally:
            ffmpeg_installed.set()

    # we parallelize the installation of the dependencies
    # TODO: we could maybe use a ThreadPoolExecutor to use Future instead of manually checking
    start_worker_thread(install_vosk, name="vosk-install-async")
    start_worker_thread(install_ffmpeg, name="ffmpeg-install-async")


@pytest.fixture(autouse=True)
def transcribe_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.transcribe_api())


class TestTranscribe:
    @pytest.fixture(scope="class", autouse=True)
    def pre_install_dependencies(self):
        if not ffmpeg_installed.is_set() or not vosk_installed.is_set():
            install_async()

        start = int(time.time())
        assert vosk_installed.wait(
            timeout=INSTALLATION_TIMEOUT
        ), "gave up waiting for Vosk to install"
        elapsed = int(time.time() - start)
        assert ffmpeg_installed.wait(
            timeout=INSTALLATION_TIMEOUT - elapsed
        ), "gave up waiting for ffmpeg to install"
        LOG.info("Spent %s seconds downloading transcribe dependencies", int(time.time() - start))

        assert not installation_errored.is_set(), "installation of transcribe dependencies failed"
        yield

    @staticmethod
    def _wait_transcription_job(
        transcribe_client: ServiceLevelClientFactory, transcribe_job_name: str
    ) -> bool:
        def is_transcription_done():
            transcription_job = transcribe_client.get_transcription_job(
                TranscriptionJobName=transcribe_job_name
            )
            return transcription_job["TranscriptionJob"]["TranscriptionJobStatus"] == "COMPLETED"

        if not poll_condition(condition=is_transcription_done, timeout=60, interval=2):
            LOG.warning(
                "Timed out while awaiting for transcription of job with transcription job name:'%s'.",
                transcribe_job_name,
            )
            return False
        else:
            return True

    @markers.skip_offline
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..TranscriptionJob..Settings",
            "$..Error..Code",
        ]
    )
    def test_transcribe_happy_path(self, transcribe_create_job, snapshot, aws_client):
        file_path = os.path.join(BASEDIR, "../../files/en-gb.wav")
        job_name = transcribe_create_job(audio_file=file_path)
        aws_client.transcribe.get_transcription_job(TranscriptionJobName=job_name)

        def is_transcription_done():
            transcription_status = aws_client.transcribe.get_transcription_job(
                TranscriptionJobName=job_name
            )
            return transcription_status["TranscriptionJob"]["TranscriptionJobStatus"] == "COMPLETED"

        # empirically it takes around
        # <5sec for a vosk transcription
        # ~100sec for an AWS transcription -> adjust timeout accordingly
        assert poll_condition(
            is_transcription_done, timeout=100
        ), f"could not finish transcription job: {job_name} in time"

        job = aws_client.transcribe.get_transcription_job(TranscriptionJobName=job_name)
        snapshot.match("TranscriptionJob", job)

        # delete the job again
        aws_client.transcribe.delete_transcription_job(TranscriptionJobName=job_name)

        # check if job is gone
        with pytest.raises((ClientError, NotFoundException)) as e_info:
            aws_client.transcribe.get_transcription_job(TranscriptionJobName=job_name)

        snapshot.match("GetError", e_info.value.response)

    @pytest.mark.parametrize(
        "media_file,speech",
        [
            ("../../files/en-gb.amr", "hello my name is"),
            ("../../files/en-gb.flac", "hello my name is"),
            ("../../files/en-gb.mp3", "hello my name is"),
            ("../../files/en-gb.mp4", "hello my name is"),
            ("../../files/en-gb.ogg", "hello my name is"),
            ("../../files/en-gb.webm", "hello my name is"),
            ("../../files/en-us_video.mkv", "one of the most vital"),
            ("../../files/en-us_video.mp4", "one of the most vital"),
        ],
    )
    @markers.aws.needs_fixing
    def test_transcribe_supported_media_formats(
        self, transcribe_create_job, media_file, speech, aws_client
    ):
        file_path = os.path.join(BASEDIR, media_file)
        job_name = transcribe_create_job(audio_file=file_path)

        def _assert_transcript():
            transcription_status = aws_client.transcribe.get_transcription_job(
                TranscriptionJobName=job_name
            )
            assert transcription_status["TranscriptionJob"]["TranscriptionJobStatus"] == "COMPLETED"
            # Ensure transcript can be retrieved from S3
            s3_uri = urlparse(
                transcription_status["TranscriptionJob"]["Transcript"]["TranscriptFileUri"],
                allow_fragments=False,
            )
            data = aws_client.s3.get_object(
                Bucket=s3_uri.path.split("/")[1],
                Key="/".join(s3_uri.path.split("/")[2:]).split("?")[0],
            )
            content = to_str(data["Body"].read())
            assert speech in content

        retry(_assert_transcript, retries=30, sleep=2)

    @markers.aws.needs_fixing
    def test_transcribe_unsupported_media_format_failure(self, transcribe_create_job, aws_client):
        # Ensure transcribing an empty file fails
        file_path = new_tmp_file()
        job_name = transcribe_create_job(audio_file=file_path)

        def _assert_transcript():
            transcription_status = aws_client.transcribe.get_transcription_job(
                TranscriptionJobName=job_name
            )
            assert transcription_status["TranscriptionJob"]["TranscriptionJobStatus"] == "FAILED"

        retry(_assert_transcript, retries=10, sleep=3)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..TranscriptionJob..Settings", "$..TranscriptionJob..Transcript", "$..Error..Code"]
    )
    def test_get_transcription_job(self, transcribe_create_job, snapshot, aws_client):
        file_path = os.path.join(BASEDIR, "../../files/en-gb.wav")
        job_name = transcribe_create_job(audio_file=file_path)

        job = aws_client.transcribe.get_transcription_job(TranscriptionJobName=job_name)

        snapshot.match("GetJob", job)

        with pytest.raises((ClientError, NotFoundException)) as e_info:
            aws_client.transcribe.get_transcription_job(TranscriptionJobName="non-existent")

        snapshot.match("GetError", e_info.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..NextToken", "$..TranscriptionJobSummaries..OutputLocationType"]
    )
    def test_list_transcription_jobs(self, transcribe_create_job, snapshot, aws_client):
        file_path = os.path.join(BASEDIR, "../../files/en-gb.wav")
        transcribe_create_job(audio_file=file_path)

        jobs = aws_client.transcribe.list_transcription_jobs()

        # there are potentially multiple transcription jobs on AWS - ordered by creation date
        # we only care about the newest one that we just created
        jobs["TranscriptionJobSummaries"] = jobs["TranscriptionJobSummaries"][0]

        snapshot.match("ListJobs", jobs)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error..Code"])
    def test_failing_deletion(self, snapshot, aws_client):
        # successful deletion is tested in the happy path test
        # this tests a failed deletion
        with pytest.raises((ClientError, NotFoundException)) as e_info:
            aws_client.transcribe.delete_transcription_job(TranscriptionJobName="non-existent")

        snapshot.match("MissingLanguageCode", e_info.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..MissingLanguageCode..Message", "$..MalformedLanguageCode..Message"]
    )
    def test_failing_start_transcription_job(self, s3_bucket, snapshot, aws_client):
        transcription_job = f"test-transcribe-{short_uid()}"
        test_key = "test-clip.wav"
        file_path = os.path.join(BASEDIR, "../../files/en-gb.wav")

        with open(file_path, "rb") as f:
            aws_client.s3.upload_fileobj(f, s3_bucket, test_key)

        # missing language code
        with pytest.raises((ClientError, BadRequestException)) as e_info:
            aws_client.transcribe.start_transcription_job(
                TranscriptionJobName=transcription_job,
                Media={"MediaFileUri": f"s3://{s3_bucket}/{test_key}"},
            )

        snapshot.match("MissingLanguageCode", e_info.value.response)

        # malformed language code
        language_code = "non-existent"
        with pytest.raises((ClientError, BadRequestException)) as e_info:
            aws_client.transcribe.start_transcription_job(
                TranscriptionJobName=transcription_job,
                LanguageCode=language_code,
                Media={"MediaFileUri": f"s3://{s3_bucket}/{test_key}"},
            )
        snapshot.match("MalformedLanguageCode", e_info.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..TranscriptionJob..Settings", "$..TranscriptionJob..Transcript"]
    )
    @pytest.mark.parametrize(
        "output_bucket,output_key",
        [
            ("test-output-bucket-2", None),  # with output bucket and without output key
            (
                "test-output-bucket-3",
                "test-output",
            ),  # with output bucket and output key without .json
            (
                "test-output-bucket-4",
                "test-output.json",
            ),  # with output bucket and output key with .json
            (
                "test-output-bucket-5",
                "test-files/test-output.json",
            ),  # with output bucket and with folder key with .json
            (
                "test-output-bucket-6",
                "test-files/test-output",
            ),  # with output bucket and with folder key without .json
            (None, None),  # without output bucket and output key
        ],
    )
    def test_transcribe_start_job(
        self,
        output_bucket,
        output_key,
        s3_bucket,
        s3_create_bucket,
        cleanups,
        snapshot,
        aws_client,
    ):
        file_path = os.path.join(BASEDIR, "../../files/en-gb.wav")
        test_key = "test-clip.wav"
        transcribe_job_name = f"test-transcribe-job-{short_uid()}"
        params = {
            "TranscriptionJobName": transcribe_job_name,
            "LanguageCode": "en-GB",
            "Media": {"MediaFileUri": f"s3://{s3_bucket}/{test_key}"},
        }

        def _cleanup():
            objects = aws_client.s3.list_objects_v2(Bucket=output_bucket)
            if "Contents" in objects:
                for obj in objects["Contents"]:
                    aws_client.s3.delete_object(Bucket=output_bucket, Key=obj["Key"])
            aws_client.s3.delete_bucket(Bucket=output_bucket)

        if output_bucket is not None:
            params["OutputBucketName"] = output_bucket
            s3_create_bucket(Bucket=output_bucket)
            cleanups.append(_cleanup)
        if output_key is not None:
            params["OutputKey"] = output_key

        with open(file_path, "rb") as f:
            aws_client.s3.upload_fileobj(f, s3_bucket, test_key)

        response_start_job = aws_client.transcribe.start_transcription_job(**params)
        self._wait_transcription_job(aws_client.transcribe, params["TranscriptionJobName"])
        snapshot.match("response-start-job", response_start_job)
        response_get_transcribe_job = aws_client.transcribe.get_transcription_job(
            TranscriptionJobName=transcribe_job_name
        )
        snapshot.match("response-get-transcribe-job", response_get_transcribe_job)

        res_delete_transcription_job = aws_client.transcribe.delete_transcription_job(
            TranscriptionJobName=transcribe_job_name
        )
        snapshot.match("delete-transcription-job", res_delete_transcription_job)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..TranscriptionJob..Transcript"])
    def test_transcribe_start_job_same_name(
        self,
        s3_bucket,
        snapshot,
        aws_client,
    ):
        file_path = os.path.join(BASEDIR, "../../files/en-gb.wav")
        test_key = "test-clip.wav"
        transcribe_job_name = f"test-transcribe-job-{short_uid()}"
        params = {
            "TranscriptionJobName": transcribe_job_name,
            "LanguageCode": "en-GB",
            "Media": {"MediaFileUri": f"s3://{s3_bucket}/{test_key}"},
        }

        with open(file_path, "rb") as f:
            aws_client.s3.upload_fileobj(f, s3_bucket, test_key)

        response_start_job = aws_client.transcribe.start_transcription_job(**params)
        snapshot.match("response-start-job", response_start_job)

        self._wait_transcription_job(aws_client.transcribe, params["TranscriptionJobName"])

        with pytest.raises((ClientError, ConflictException)) as e:
            aws_client.transcribe.start_transcription_job(**params)

        snapshot.match("same-transcription-job-name", e.value.response)

        res_delete_transcription_job = aws_client.transcribe.delete_transcription_job(
            TranscriptionJobName=transcribe_job_name
        )
        snapshot.match("delete-transcription-job", res_delete_transcription_job)
