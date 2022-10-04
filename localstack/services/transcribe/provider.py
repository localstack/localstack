import datetime
import json
import logging
import os
import threading
import wave
from pathlib import Path
from typing import Tuple
from zipfile import ZipFile

from localstack import config
from localstack.aws.api import RequestContext, handler
from localstack.aws.api.transcribe import (
    BadRequestException,
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
from localstack.services.transcribe.models import TranscribeStore, transcribe_stores
from localstack.utils.aws import aws_stack
from localstack.utils.files import new_tmp_file
from localstack.utils.http import download
from localstack.utils.strings import short_uid
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
    "zh-CN": "vosk-model-small-cn-0.3",
}

LANGUAGE_MODEL_DIR = Path(config.dirs.cache) / "vosk"

os.environ["VOSK_MODEL_PATH"] = str(LANGUAGE_MODEL_DIR)

# Vosk must be imported only after setting the required env vars
from vosk import MODEL_PRE_URL, KaldiRecognizer, Model, SetLogLevel  # noqa

# Suppress Vosk logging
SetLogLevel(-1)

# Mutex for when downloading models
_DL_LOCK = threading.Lock()


class TranscribeProvider(TranscribeApi):

    #
    # Handlers
    #

    def get_transcription_job(
        self, context: RequestContext, transcription_job_name: TranscriptionJobName
    ) -> GetTranscriptionJobResponse:
        store = transcribe_stores[context.account_id][context.region]

        if job := store.transcription_jobs.get(transcription_job_name):
            return GetTranscriptionJobResponse(TranscriptionJob=job)

        raise NotFoundException(
            "The requested job couldn't be found. Check the job name and try your request again."
        )

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
        store.transcription_jobs[job_name] = TranscriptionJob(
            TranscriptionJobName=job_name,
            LanguageCode=language_code,
            Media=media,
            CreationTime=datetime.datetime.utcnow(),
            StartTime=datetime.datetime.utcnow(),
            TranscriptionJobStatus=TranscriptionJobStatus.QUEUED,
        )

        start_thread(self._run_transcription_job, (store, job_name))

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
            s3_client = aws_stack.connect_to_service("s3")
            s3_path = job["Media"]["MediaFileUri"]
            bucket, _, key = s3_path.removeprefix("s3://").partition("/")
            s3_client.download_file(Bucket=bucket, Key=key, Filename=file_path)

            # Check if file is valid wav
            audio = wave.open(file_path, "rb")
            if (
                audio.getnchannels() != 1
                or audio.getsampwidth() != 2
                or audio.getcomptype() != "NONE"
            ):
                # Fail job
                failure_reason = "Audio file must be mono PCM WAV format"
                raise RuntimeError()

            # Prepare transcriber
            language_code = job["LanguageCode"]
            model_name = LANGUAGE_MODELS[language_code]
            self.download_model(model_name)
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
                        "type": "pronounciation",
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
            output_key = short_uid() + ".json"
            s3_client.put_object(Bucket=bucket, Key=output_key, Body=json.dumps(output))

            # Update job details
            job["CompletionTime"] = datetime.datetime.utcnow()
            job["TranscriptionJobStatus"] = TranscriptionJobStatus.COMPLETED
            job["Transcript"] = Transcript(TranscriptFileUri=f"s3://{bucket}/{output_key}")
            job["MediaFormat"] = MediaFormat.wav

            LOG.info("Transcription job completed: %s", job_name)

        except Exception as exc:
            job["FailureReason"] = failure_reason or str(exc)
            job["TranscriptionJobStatus"] = TranscriptionJobStatus.FAILED

            LOG.warning("Transcription job %s failed: %s", job_name, job["FailureReason"])
