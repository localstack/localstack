import datetime
import json
import logging
import os
import threading
import wave
from functools import cache
from pathlib import Path
from typing import Tuple
from zipfile import ZipFile

from localstack import config
from localstack.aws.api import RequestContext, handler
from localstack.aws.api.transcribe import (
    BadRequestException,
    ConflictException,
    GetTranscriptionJobResponse,
    ListTranscriptionJobsResponse,
    MaxResults,
    MediaFormat,
    NextToken,
    NotFoundException,
    StartTranscriptionJobRequest,
    StartTranscriptionJobResponse,
    TranscribeApi,
    Transcript,
    TranscriptionJob,
    TranscriptionJobName,
    TranscriptionJobStatus,
    TranscriptionJobSummary,
)
from localstack.aws.connect import connect_to
from localstack.packages.ffmpeg import ffmpeg_package
from localstack.services.s3.utils import (
    get_bucket_and_key_from_presign_url,
    get_bucket_and_key_from_s3_uri,
)
from localstack.services.transcribe.models import TranscribeStore, transcribe_stores
from localstack.services.transcribe.packages import vosk_package
from localstack.utils.files import new_tmp_file
from localstack.utils.http import download
from localstack.utils.run import run
from localstack.utils.threads import start_thread

LOG = logging.getLogger(__name__)

# Map of language codes to language models
LANGUAGE_MODELS = {
    "en-IN": "vosk-model-small-en-in-0.4",
    "en-US": "vosk-model-small-en-us-0.15",
    "en-GB": "vosk-model-small-en-gb-0.15",
    "fr-FR": "vosk-model-small-fr-0.22",
    "de-DE": "vosk-model-small-de-0.15",
    "es-ES": "vosk-model-small-es-0.22",
    "it-IT": "vosk-model-small-it-0.4",
    "pt-BR": "vosk-model-small-pt-0.3",
    "ru-RU": "vosk-model-small-ru-0.4",
    "nl-NL": "vosk-model-small-nl-0.22",
    "tr-TR": "vosk-model-small-tr-0.3",
    "hi-IN": "vosk-model-small-hi-0.22",
    "ja-JP": "vosk-model-small-ja-0.22",
    "fa-IR": "vosk-model-small-fa-0.5",
    "vi-VN": "vosk-model-small-vn-0.3",
    "zh-CN": "vosk-model-small-cn-0.3",
}

LANGUAGE_MODEL_DIR = Path(config.dirs.cache) / "vosk"

# List of ffmpeg format names that correspond the supported formats by AWS
# See https://docs.aws.amazon.com/transcribe/latest/dg/how-input.html
SUPPORTED_FORMAT_NAMES = {
    "amr": MediaFormat.amr,
    "flac": MediaFormat.flac,
    "mp3": MediaFormat.mp3,
    "mov,mp4,m4a,3gp,3g2,mj2": MediaFormat.mp4,
    "ogg": MediaFormat.ogg,
    "matroska,webm": MediaFormat.webm,
    "wav": MediaFormat.wav,
}

# Mutex for when downloading models
_DL_LOCK = threading.Lock()


class TranscribeProvider(TranscribeApi):
    def get_transcription_job(
        self, context: RequestContext, transcription_job_name: TranscriptionJobName
    ) -> GetTranscriptionJobResponse:
        store = transcribe_stores[context.account_id][context.region]

        if job := store.transcription_jobs.get(transcription_job_name):
            # fetch output key and output bucket
            output_bucket, output_key = get_bucket_and_key_from_presign_url(
                job["Transcript"]["TranscriptFileUri"]
            )
            job["Transcript"]["TranscriptFileUri"] = connect_to().s3.generate_presigned_url(
                "get_object",
                Params={"Bucket": output_bucket, "Key": output_key},
                ExpiresIn=60 * 15,
            )
            return GetTranscriptionJobResponse(TranscriptionJob=job)

        raise NotFoundException(
            "The requested job couldn't be found. Check the job name and try your request again."
        )

    @staticmethod
    @cache
    def _setup_vosk() -> None:
        # Install and configure vosk
        vosk_package.install()

        # Vosk must be imported only after setting the required env vars
        os.environ["VOSK_MODEL_PATH"] = str(LANGUAGE_MODEL_DIR)
        from vosk import SetLogLevel  # noqa

        # Suppress Vosk logging
        SetLogLevel(-1)

    @handler("StartTranscriptionJob", expand=False)
    def start_transcription_job(
        self,
        context: RequestContext,
        request: StartTranscriptionJobRequest,
    ) -> StartTranscriptionJobResponse:
        job_name = request["TranscriptionJobName"]
        media = request["Media"]
        language_code = request.get("LanguageCode")

        if not language_code:
            raise BadRequestException("Language code is missing")

        if language_code not in LANGUAGE_MODELS:
            raise BadRequestException(f"Language code must be one of {LANGUAGE_MODELS.keys()}")

        store = transcribe_stores[context.account_id][context.region]

        if job_name in store.transcription_jobs:
            raise ConflictException(
                "The requested job name already exists. Use a different job name."
            )

        s3_path = request["Media"]["MediaFileUri"]
        output_bucket = request.get("OutputBucketName", get_bucket_and_key_from_s3_uri(s3_path)[0])
        output_key = request.get("OutputKey")

        if not output_key:
            output_key = f"{job_name}.json"

        s3_client = connect_to().s3

        # the presign url is valid for 15 minutes
        presign_url = s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": output_bucket, "Key": output_key},
            ExpiresIn=60 * 15,
        )

        transcript = Transcript(TranscriptFileUri=presign_url)

        job = TranscriptionJob(
            TranscriptionJobName=job_name,
            LanguageCode=language_code,
            Media=media,
            CreationTime=datetime.datetime.utcnow(),
            StartTime=datetime.datetime.utcnow(),
            TranscriptionJobStatus=TranscriptionJobStatus.QUEUED,
            Transcript=transcript,
        )
        store.transcription_jobs[job_name] = job

        start_thread(self._run_transcription_job, (store, job_name))

        return StartTranscriptionJobResponse(TranscriptionJob=job)

    def list_transcription_jobs(
        self,
        context: RequestContext,
        status: TranscriptionJobStatus = None,
        job_name_contains: TranscriptionJobName = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListTranscriptionJobsResponse:
        store = transcribe_stores[context.account_id][context.region]
        summaries = []
        for job in store.transcription_jobs.values():
            summaries.append(
                TranscriptionJobSummary(
                    TranscriptionJobName=job["TranscriptionJobName"],
                    LanguageCode=job["LanguageCode"],
                    CreationTime=job["CreationTime"],
                    StartTime=job["StartTime"],
                    TranscriptionJobStatus=job["TranscriptionJobStatus"],
                    CompletionTime=job.get("CompletionTime"),
                    FailureReason=job.get("FailureReason"),
                )
            )

        return ListTranscriptionJobsResponse(TranscriptionJobSummaries=summaries)

    def delete_transcription_job(
        self, context: RequestContext, transcription_job_name: TranscriptionJobName
    ) -> None:
        store = transcribe_stores[context.account_id][context.region]

        if transcription_job_name not in store.transcription_jobs:
            raise NotFoundException(
                "The requested job couldn't be found. Check the job name and try your request again."
            )

        store.transcription_jobs.pop(transcription_job_name)

    #
    # Utils
    #

    @staticmethod
    def download_model(name: str):
        """
        Download a Vosk language model to LocalStack cache directory. Do nothing if model is already downloaded.

        While can Vosk also download a model if not available locally, it saves it to a
        non-configurable location ~/.cache/vosk.
        """
        model_path = LANGUAGE_MODEL_DIR / name

        with _DL_LOCK:
            if (model_path).exists():
                return
            else:
                model_path.mkdir(parents=True)

            model_zip_path = str(model_path) + ".zip"

            LOG.debug("Downloading language model: %s", model_path.name)

            from vosk import MODEL_PRE_URL  # noqa

            download(
                MODEL_PRE_URL + str(model_path.name) + ".zip", model_zip_path, verify_ssl=False
            )

            LOG.debug("Extracting language model: %s", model_path.name)
            with ZipFile(model_zip_path, "r") as model_ref:
                model_ref.extractall(model_path.parent)

            Path(model_zip_path).unlink()

    #
    # Threads
    #

    def _run_transcription_job(self, args: Tuple[TranscribeStore, str]):
        store, job_name = args

        job = store.transcription_jobs[job_name]
        job["StartTime"] = datetime.datetime.utcnow()
        job["TranscriptionJobStatus"] = TranscriptionJobStatus.IN_PROGRESS

        failure_reason = None

        try:
            LOG.debug("Starting transcription: %s", job_name)

            # Get file from S3
            file_path = new_tmp_file()
            s3_client = connect_to().s3
            s3_path = job["Media"]["MediaFileUri"]
            bucket, _, key = s3_path.removeprefix("s3://").partition("/")
            s3_client.download_file(Bucket=bucket, Key=key, Filename=file_path)

            ffmpeg_package.install()
            ffmpeg_bin = ffmpeg_package.get_installer().get_ffmpeg_path()
            ffprobe_bin = ffmpeg_package.get_installer().get_ffprobe_path()

            LOG.debug("Determining media format")
            # TODO set correct failure_reason if ffprobe execution fails
            ffprobe_output = json.loads(
                run(
                    f"{ffprobe_bin} -show_streams -show_format -print_format json -hide_banner -v error {file_path}"
                )
            )
            format = ffprobe_output["format"]["format_name"]
            LOG.debug(f"Media format detected as: {format}")
            job["MediaFormat"] = SUPPORTED_FORMAT_NAMES[format]

            # Determine the sample rate of input audio if possible
            for stream in ffprobe_output["streams"]:
                if stream["codec_type"] == "audio":
                    job["MediaSampleRateHertz"] = int(stream["sample_rate"])

            if format in SUPPORTED_FORMAT_NAMES:
                wav_path = new_tmp_file(suffix=".wav")
                LOG.debug("Transcoding media to wav")
                # TODO set correct failure_reason if ffmpeg execution fails
                run(
                    f"{ffmpeg_bin} -y -nostdin -loglevel quiet -i '{file_path}' -ar 16000 -ac 1 '{wav_path}'"
                )
            else:
                failure_reason = f"Unsupported media format: {format}"
                raise RuntimeError()

            # Check if file is valid wav
            audio = wave.open(wav_path, "rb")
            if (
                audio.getnchannels() != 1
                or audio.getsampwidth() != 2
                or audio.getcomptype() != "NONE"
            ):
                # Fail job
                failure_reason = (
                    "Audio file must be mono PCM WAV format. Transcoding may have failed. "
                )
                raise RuntimeError()

            # Prepare transcriber
            language_code = job["LanguageCode"]
            model_name = LANGUAGE_MODELS[language_code]
            self._setup_vosk()
            self.download_model(model_name)
            from vosk import KaldiRecognizer, Model  # noqa

            model = Model(model_name=model_name)

            tc = KaldiRecognizer(model, audio.getframerate())
            tc.SetWords(True)
            tc.SetPartialWords(True)

            # Start transcription
            while True:
                data = audio.readframes(4000)
                if len(data) == 0:
                    break
                tc.AcceptWaveform(data)

            tc_result = json.loads(tc.FinalResult())

            # Convert to AWS format
            items = []
            for unigram in tc_result["result"]:
                items.append(
                    {
                        "start_time": unigram["start"],
                        "end_time": unigram["end"],
                        "type": "pronunciation",
                        "alternatives": [
                            {
                                "confidence": unigram["conf"],
                                "content": unigram["word"],
                            }
                        ],
                    }
                )
            output = {
                "jobName": job_name,
                "status": TranscriptionJobStatus.COMPLETED,
                "results": {
                    "transcripts": [
                        {
                            "transcript": tc_result["text"],
                        }
                    ],
                    "items": items,
                },
            }

            # Save to S3
            output_s3_path = job["Transcript"]["TranscriptFileUri"]
            output_bucket, output_key = get_bucket_and_key_from_presign_url(output_s3_path)
            s3_client.put_object(Bucket=output_bucket, Key=output_key, Body=json.dumps(output))

            # Update job details
            job["CompletionTime"] = datetime.datetime.utcnow()
            job["TranscriptionJobStatus"] = TranscriptionJobStatus.COMPLETED
            job["MediaFormat"] = MediaFormat.wav

            LOG.info("Transcription job completed: %s", job_name)

        except Exception as exc:
            job["FailureReason"] = failure_reason or str(exc)
            job["TranscriptionJobStatus"] = TranscriptionJobStatus.FAILED

            LOG.exception("Transcription job %s failed: %s", job_name, job["FailureReason"])
