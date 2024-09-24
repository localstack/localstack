import logging

import pytest

from localstack.logging.format import (
    AddFormattedAttributes,
    AwsTraceLoggingFormatter,
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


class TestTraceLoggingFormatter:
    @pytest.fixture
    def handler(self):
        handler = TestHandler()

        handler.setLevel(logging.DEBUG)
        handler.setFormatter(AwsTraceLoggingFormatter())
        handler.addFilter(AddFormattedAttributes())
        return handler

    @pytest.fixture
    def logger(self, handler):
        logger = logging.getLogger("test.logger")

        # avoid propagation to parent loggers
        logger.propagate = False
        logger.addHandler(handler)
        return logger

    def test_aws_trace_logging_contains_payload(self, handler, logger):
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

    def test_aws_trace_logging_replaces_bigger_blobs(self, handler, logger):
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
