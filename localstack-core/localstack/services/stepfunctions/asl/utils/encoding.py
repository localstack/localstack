import datetime
import json
from json import JSONEncoder
from typing import Any, Optional


class _DateTimeEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()
        else:
            return str(obj)


def to_json_str(obj: Any, separators: Optional[tuple[str, str]] = None) -> str:
    return json.dumps(obj, cls=_DateTimeEncoder, separators=separators)
