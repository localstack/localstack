from __future__ import annotations

import logging
from unittest import mock

from localstack import config

LOG = logging.getLogger(__name__)

if config.CFN_TRACING_ENABLE:
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as e:
        LOG.warning(
            f"config.CFN_TRACING_ENABLE=1 but telemetry packages could not be imported: {e}"
        )
        config.CFN_TRACING_ENABLE = False


class TracingRecorder:
    def __init__(self, name: str):
        self.name = name
        if config.CFN_TRACING_ENABLE:
            self.resource = Resource(attributes={SERVICE_NAME: self.name})
            self.provider = TracerProvider(resource=self.resource)

    def connect_to(self, endpoint: str) -> TracingRecorder:
        if config.CFN_TRACING_ENABLE:
            processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
            self.provider.add_span_processor(processor)
            trace.set_tracer_provider(self.provider)
        return self

    def get_tracer(self, name: str) -> trace.Tracer | mock.MagicMock:
        if config.CFN_TRACING_ENABLE:
            return trace.get_tracer(name)
        else:
            return mock.MagicMock()
