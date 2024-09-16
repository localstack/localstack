import time
from datetime import date, datetime, timezone, tzinfo
from typing import Optional

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"
TIMESTAMP_FORMAT_TZ = "%Y-%m-%dT%H:%M:%SZ"
TIMESTAMP_FORMAT_MICROS = "%Y-%m-%dT%H:%M:%S.%fZ"
TIMESTAMP_READABLE_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def isoformat_milliseconds(t) -> str:
    try:
        return t.isoformat(timespec="milliseconds")
    except TypeError:
        return t.isoformat()[:-3]


def timestamp(time=None, format: str = TIMESTAMP_FORMAT) -> str:
    if not time:
        time = datetime.utcnow()
    if isinstance(time, (int, float)):
        time = datetime.fromtimestamp(time)
    return time.strftime(format)


def timestamp_millis(time=None) -> str:
    microsecond_time = timestamp(time=time, format=TIMESTAMP_FORMAT_MICROS)
    # truncating microseconds to milliseconds, while leaving the "Z" indicator
    return microsecond_time[:-4] + microsecond_time[-1]


def iso1806_to_epoch(t: str) -> float:
    return datetime.fromisoformat(t).timestamp()


def epoch_to_iso1806(ts: int) -> str:
    return datetime.utcfromtimestamp(ts).isoformat()


def epoch_timestamp() -> float:
    return time.time()


def parse_timestamp(ts_str: str) -> datetime:
    for ts_format in [
        TIMESTAMP_FORMAT,
        TIMESTAMP_FORMAT_TZ,
        TIMESTAMP_FORMAT_MICROS,
        TIMESTAMP_READABLE_FORMAT,
    ]:
        try:
            return datetime.strptime(ts_str, ts_format)
        except ValueError:
            pass
    raise Exception("Unable to parse timestamp string with any known formats: %s" % ts_str)


def now(millis: bool = False, tz: Optional[tzinfo] = None) -> int:
    return mktime(datetime.now(tz=tz), millis=millis)


def now_utc(millis: bool = False) -> int:
    return now(millis, timezone.utc)


def today_no_time() -> int:
    return mktime(datetime.combine(date.today(), datetime.min.time()))


def mktime(ts: datetime, millis: bool = False) -> int:
    if millis:
        return int(ts.timestamp() * 1000)
    return int(ts.timestamp())
