"""Tools for formatting localstack logs."""
import logging
from functools import lru_cache
from typing import Dict

from localstack.utils.numbers import format_bytes

MAX_THREAD_NAME_LEN = 12
MAX_NAME_LEN = 26

LOG_FORMAT = f"%(asctime)s.%(msecs)03d %(ls_level)5s --- [%(ls_thread){MAX_THREAD_NAME_LEN}s] %(ls_name)-{MAX_NAME_LEN}s : %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

CUSTOM_LEVEL_NAMES = {
    50: "FATAL",
    40: "ERROR",
    30: "WARN",
    20: "INFO",
    10: "DEBUG",
}


class DefaultFormatter(logging.Formatter):
    """
    A formatter that uses ``LOG_FORMAT`` and ``LOG_DATE_FORMAT``.
    """

    def __init__(self, fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT):
        super(DefaultFormatter, self).__init__(fmt=fmt, datefmt=datefmt)


class AddFormattedAttributes(logging.Filter):
    """
    Filter that adds three attributes to a log record:

    - ls_level: the abbreviated loglevel that's max 5 characters long
    - ls_name: the abbreviated name of the logger (e.g., `l.bootstrap.install`), trimmed to ``MAX_NAME_LEN``
    - ls_thread: the abbreviated thread name (prefix trimmed, .e.g, ``omeThread-108``)
    """

    max_name_len: int
    max_thread_len: int

    def __init__(self, max_name_len: int = None, max_thread_len: int = None):
        super(AddFormattedAttributes, self).__init__()
        self.max_name_len = max_name_len if max_name_len else MAX_NAME_LEN
        self.max_thread_len = max_thread_len if max_thread_len else MAX_THREAD_NAME_LEN

    def filter(self, record):
        record.ls_level = CUSTOM_LEVEL_NAMES.get(record.levelno, record.levelname)
        record.ls_name = self._get_compressed_logger_name(record.name)
        record.ls_thread = record.threadName[-self.max_thread_len :]
        return True

    @lru_cache(maxsize=256)
    def _get_compressed_logger_name(self, name):
        return compress_logger_name(name, self.max_name_len)


def compress_logger_name(name: str, length: int) -> str:
    """
    Creates a short version of a logger name. For example ``my.very.long.logger.name`` with length=17 turns into
    ``m.v.l.logger.name``.

    :param name: the logger name
    :param length: the max length of the logger name
    :return: the compressed name
    """
    if len(name) <= length:
        return name

    parts = name.split(".")
    parts.reverse()

    new_parts = []

    # we start by assuming that all parts are collapsed
    # x.x.x requires 5 = 2n - 1 characters
    cur_length = (len(parts) * 2) - 1

    for i in range(len(parts)):
        # try to expand the current part and calculate the resulting length
        part = parts[i]
        next_len = cur_length + (len(part) - 1)

        if next_len > length:
            # if the resulting length would exceed the limit, add only the first letter of the parts of all remaining
            # parts
            new_parts += [p[0] for p in parts[i:]]

            # but if this is the first item, that means we would display nothing, so at least display as much of the
            # max length as possible
            if i == 0:
                remaining = length - cur_length
                if remaining > 0:
                    new_parts[0] = part[: (remaining + 1)]

            break

        # expanding the current part, i.e., instead of using just the one character, we add the entire part
        new_parts.append(part)
        cur_length = next_len

    new_parts.reverse()
    return ".".join(new_parts)


class TraceLoggingFormatter(logging.Formatter):
    aws_trace_log_format = (
        LOG_FORMAT
        + "; %(input_type)s(%(input)s, headers=%(request_headers)s); %(output_type)s(%(output)s, headers=%(response_headers)s)"
    )

    def __init__(self):
        super().__init__(fmt=self.aws_trace_log_format, datefmt=LOG_DATE_FORMAT)


class AwsTraceLoggingFormatter(TraceLoggingFormatter):
    bytes_length_display_threshold = 512

    def __init__(self):
        super().__init__()

    def _copy_service_dict(self, service_dict: Dict) -> Dict:
        if not isinstance(service_dict, Dict):
            return service_dict
        result = {}
        for key, value in service_dict.items():
            if isinstance(value, dict):
                result[key] = self._copy_service_dict(value)
            elif isinstance(value, bytes) and len(value) > self.bytes_length_display_threshold:
                result[key] = f"Bytes({format_bytes(len(value))})"
            elif isinstance(value, list):
                result[key] = [self._copy_service_dict(item) for item in value]
            else:
                result[key] = value
        return result

    def format(self, record: logging.LogRecord) -> str:
        record.input = self._copy_service_dict(record.input)
        record.output = self._copy_service_dict(record.output)
        return super().format(record=record)
