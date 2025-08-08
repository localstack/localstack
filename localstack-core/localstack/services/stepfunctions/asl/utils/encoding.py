import datetime
import json
from json import JSONEncoder
from typing import Any


class _DateTimeEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()
        else:
            return str(obj)


def to_json_str(obj: Any, separators: tuple[str, str] | None = None) -> str:
    return json.dumps(obj, cls=_DateTimeEncoder, separators=separators)
