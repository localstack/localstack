import dataclasses
import datetime
import json
import logging
import tempfile
import threading
from typing import IO

from localstack import config
from localstack.services.lambda_.invocation.lambda_models import InvocationResult
from localstack.utils.json import CustomEncoder

LOG = logging.getLogger(__name__)


@dataclasses.dataclass
class InvocationLogRecord:
    timestamp: datetime.datetime
    request_id: str
    function_arn: str
    payload: str
    result: InvocationResult

    def to_dict(self) -> dict:
        doc = dataclasses.asdict(self)
        doc["timestamp"] = self.timestamp.isoformat()
        doc["result"] = dataclasses.asdict(self.result)
        if isinstance(doc["result"].get("payload"), bytes):
            doc["result"]["payload"] = doc["result"]["payload"].decode("utf-8")

        return doc


class InvocationLog:
    _file: IO[bytes]
    _lock: threading.Lock

    def __init__(self):
        # 1MB in-memory buffer before rolling over to disk
        self._file = tempfile.SpooledTemporaryFile(
            max_size=1024 * 1024, mode="w+b", dir=config.dirs.data
        )
        self._lock = threading.Lock()

    def append(self, record: InvocationLogRecord):
        doc = record.to_dict()
        line = json.dumps(doc, cls=CustomEncoder) + "\n"
        # SpooledTemporaryFile might not be thread-safe for seeks and writes.
        # Since this is a global log, multiple threads might call it concurrently.
        # Adding a lock for safety.
        with self._lock:
            self._file.seek(0, 2)
            self._file.write(line.encode("utf-8"))

    def get_all(self) -> list[InvocationLogRecord]:
        with self._lock:
            self._file.seek(0)
            # We read everything into memory here anyway, as requested by return type.
            # For a true NDJSON file, we iterate over lines.
            lines = self._file.readlines()

        records = []
        for line in lines:
            if not line.strip():
                continue
            try:
                doc = json.loads(line.decode("utf-8"))
                # Restore types
                doc["timestamp"] = datetime.datetime.fromisoformat(doc["timestamp"])
                res = doc["result"]
                if res.get("payload") is not None:
                    res["payload"] = res["payload"].encode("utf-8")

                doc["result"] = InvocationResult(**res)
                records.append(InvocationLogRecord(**doc))
            except Exception:
                LOG.exception("Failed to de-serialize invocation log record")
        return records


INVOCATIONS = InvocationLog()


def log_invocation(
    timestamp: datetime.datetime,
    request_id: str,
    function_arn: str,
    payload: str,
    result: InvocationResult,
) -> None:
    record = InvocationLogRecord(timestamp, request_id, function_arn, payload, result)
    INVOCATIONS.append(record)


def get_invocations() -> list[InvocationLogRecord]:
    return INVOCATIONS.get_all()
