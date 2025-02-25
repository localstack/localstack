import logging

import pytest

from localstack.logging.format import (
    AddFormattedAttributes,
    AwsTraceLoggingFormatter,
    MaskSensitiveInputFilter,
    TraceLoggingFormatter,
    compress_logger_name,
)


def test_compress_logger_name():
    assert compress_logger_name("log", 1) == "l"
    assert compress_logger_name("log", 2) == "lo"
    assert compress_logger_name("log", 3) == "log"
    assert compress_logger_name("log", 5) == "log"
    assert compress_logger_name("my.very.long.logger.name", 1) == "m.v.l.l.n"
    assert compress_logger_name("my.very.long.logger.name", 11) == "m.v.l.l.nam"
    assert compress_logger_name("my.very.long.logger.name", 12) == "m.v.l.l.name"
    assert compress_logger_name("my.very.long.logger.name", 16) == "m.v.l.l.name"
    assert compress_logger_name("my.very.long.logger.name", 17) == "m.v.l.logger.name"
    assert compress_logger_name("my.very.long.logger.name", 24) == "my.very.long.logger.name"


class TestHandler(logging.Handler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.messages = []

    def emit(self, record):
        self.messages.append(self.format(record))


class CustomMaskSensitiveInputFilter(MaskSensitiveInputFilter):
    sensitive_keys = ["sensitive_key"]

    def __init__(self):
        super(CustomMaskSensitiveInputFilter, self).__init__(self.sensitive_keys)


@pytest.fixture
def get_logger():
    handlers: list[logging.Handler] = []
    logger = logging.getLogger("test.logger")

    def _get_logger(handler: logging.Handler) -> logging.Logger:
        handlers.append(handler)

        # avoid propagation to parent loggers
        logger.propagate = False
        logger.addHandler(handler)
        return logger

    yield _get_logger

    for handler in handlers:
        logger.removeHandler(handler)


class TestTraceLoggingFormatter:
    @pytest.fixture
    def handler(self):
        handler = TestHandler()

        handler.setLevel(logging.DEBUG)
        handler.setFormatter(AwsTraceLoggingFormatter())
        handler.addFilter(AddFormattedAttributes())
        return handler

    def test_aws_trace_logging_contains_payload(self, handler, get_logger):
        logger = get_logger(handler)
        logger.info(
            "AWS %s.%s => %s",
            "TestService",
            "Operation",
            "201",
            extra={
                # context
                "account_id": "123123123123",
                "region": "invalid-region",
                # request
                "input_type": "RequestShape",
                "input": {"test": "request"},
                "request_headers": {"request": "header"},
                # response
                "output_type": "OutputShape",
                "output": {"test": "response"},
                "response_headers": {"response": "header"},
            },
        )
        log_message = handler.messages[0]
        assert "TestService" in log_message
        assert "RequestShape" in log_message
        assert "OutputShape" in log_message
        assert "{'test': 'request'}" in log_message
        assert "{'test': 'response'}" in log_message

        assert "{'request': 'header'}" in log_message
        assert "{'response': 'header'}" in log_message

    def test_aws_trace_logging_replaces_bigger_blobs(self, handler, get_logger):
        logger = get_logger(handler)
        logger.info(
            "AWS %s.%s => %s",
            "TestService",
            "Operation",
            "201",
            extra={
                # context
                "account_id": "123123123123",
                "region": "invalid-region",
                # request
                "input_type": "RequestShape",
                "input": {"request": b"a" * 1024},
                "request_headers": {"request": "header"},
                # response
                "output_type": "OutputShape",
                "output": {"response": b"a" * 1025},
                "response_headers": {"response": "header"},
            },
        )
        log_message = handler.messages[0]
        assert "TestService" in log_message
        assert "RequestShape" in log_message
        assert "OutputShape" in log_message
        assert "{'request': 'Bytes(1.024KB)'}" in log_message
        assert "{'response': 'Bytes(1.025KB)'}" in log_message

        assert "{'request': 'header'}" in log_message
        assert "{'response': 'header'}" in log_message


class TestMaskSensitiveInputFilter:
    @pytest.fixture
    def handler(self):
        handler = TestHandler()

        handler.setLevel(logging.DEBUG)
        handler.setFormatter(TraceLoggingFormatter())
        handler.addFilter(AddFormattedAttributes())
        handler.addFilter(CustomMaskSensitiveInputFilter())
        return handler

    def test_input_payload_masked(self, handler, get_logger):
        logger = get_logger(handler)
        logger.info(
            "%s %s => %d",
            "POST",
            "/_localstack/path",
            200,
            extra={
                # request
                "input_type": "Request",
                "input": b'{"sensitive_key": "sensitive", "other_key": "value"}',
                "request_headers": {},
                # response
                "output_type": "Response",
                "output": "StreamingBody(unknown)",
                "response_headers": {},
            },
        )
        log_message = handler.messages[0]
        assert """b'{"sensitive_key": "******", "other_key": "value"}'""" in log_message

    def test_input_leave_null_unmasked(self, handler, get_logger):
        logger = get_logger(handler)
        logger.info(
            "%s %s => %d",
            "POST",
            "/_localstack/path",
            200,
            extra={
                "input_type": "Request",
                "input": b'{"sensitive_key": null, "other_key": "value"}',
                "request_headers": {},
                # response
                "output_type": "Response",
                "output": "StreamingBody(unknown)",
                "response_headers": {},
            },
        )
        log_message = handler.messages[0]
        assert """b'{"sensitive_key": null, "other_key": "value"}'""" in log_message
