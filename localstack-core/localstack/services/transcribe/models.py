from localstack.aws.api.transcribe import TranscriptionJob, TranscriptionJobName
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class TranscribeStore(BaseStore):
    transcription_jobs: dict[TranscriptionJobName, TranscriptionJob] = LocalAttribute(default=dict)


transcribe_stores = AccountRegionBundle("transcribe", TranscribeStore)
