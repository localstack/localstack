import json

from localstack.services.stores import AccountRegionBundle, BaseStore, LocalRedisResource
from localstack.utils.aws.arns import transcribe_transcription_job_arn
from localstack.utils.json import CustomEncoder


class TranscribeStore(BaseStore):
    transcription_jobs = LocalRedisResource(
        name="transcription-job",
        arn_builder=transcribe_transcription_job_arn,
        serializer=lambda obj: json.dumps(obj, cls=CustomEncoder),
        deserializer=json.loads,
    )


transcribe_stores = AccountRegionBundle("transcribe", TranscribeStore)
