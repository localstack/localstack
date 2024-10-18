# This file is part of LocalStack.
# It is adapted from aws-xray-sdk-python licensed under the Apache License 2.0.
# You may obtain a copy of the Apache License 2.0 at http://www.apache.org/licenses/LICENSE-2.0
# Original source: https://github.com/aws/aws-xray-sdk-python/blob/master/aws_xray_sdk/core/models/trace_header.py
# Modifications:
# * Add optional lineage field for https://docs.aws.amazon.com/lambda/latest/dg/invocation-recursion.html
# * Add ensure_root_exists() to generate root trace id

import logging

from localstack.utils.xray.traceid import TraceId

log = logging.getLogger(__name__)

ROOT = "Root"
PARENT = "Parent"
SAMPLE = "Sampled"
SELF = "Self"
LINEAGE = "Lineage"

HEADER_DELIMITER = ";"


class TraceHeader:
    """
    The sampling decision and trace ID are added to HTTP requests in
    tracing headers named ``X-Amzn-Trace-Id``. The first X-Ray-integrated
    service that the request hits adds a tracing header, which is read
    by the X-Ray SDK and included in the response. Learn more about
    `Tracing Header <http://docs.aws.amazon.com/xray/latest/devguide/xray-concepts.html#xray-concepts-tracingheader>`_.
    """

    def __init__(self, root=None, parent=None, sampled=None, data=None, lineage=None):
        """
        :param str root: trace id
        :param str parent: parent id
        :param int sampled: 0 means not sampled, 1 means sampled
        :param dict data: arbitrary data fields
        :param str lineage: lineage
        """
        self._root = root
        self._parent = parent
        self._sampled = None
        self._lineage = lineage
        self._data = data

        if sampled is not None:
            if sampled == "?":
                self._sampled = sampled
            if sampled is True or sampled == "1" or sampled == 1:
                self._sampled = 1
            if sampled is False or sampled == "0" or sampled == 0:
                self._sampled = 0

    @classmethod
    def from_header_str(cls, header):
        """
        Create a TraceHeader object from a tracing header string
        extracted from a http request headers.
        """
        if not header:
            return cls()

        try:
            params = header.strip().split(HEADER_DELIMITER)
            header_dict = {}
            data = {}

            for param in params:
                entry = param.split("=")
                key = entry[0]
                if key in (ROOT, PARENT, SAMPLE, LINEAGE):
                    header_dict[key] = entry[1]
                # Ignore any "Self=" trace ids injected from ALB.
                elif key != SELF:
                    data[key] = entry[1]

            return cls(
                root=header_dict.get(ROOT, None),
                parent=header_dict.get(PARENT, None),
                sampled=header_dict.get(SAMPLE, None),
                lineage=header_dict.get(LINEAGE, None),
                data=data,
            )

        except Exception:
            log.warning("malformed tracing header %s, ignore.", header)
            return cls()

    def to_header_str(self):
        """
        Convert to a tracing header string that can be injected to
        outgoing http request headers.
        """
        h_parts = []
        if self.root:
            h_parts.append(ROOT + "=" + self.root)
        if self.parent:
            h_parts.append(PARENT + "=" + self.parent)
        if self.sampled is not None:
            h_parts.append(SAMPLE + "=" + str(self.sampled))
        if self.lineage is not None:
            h_parts.append(LINEAGE + "=" + str(self.lineage))
        if self.data:
            for key in self.data:
                h_parts.append(key + "=" + self.data[key])

        return HEADER_DELIMITER.join(h_parts)

    def ensure_root_exists(self):
        """
        Ensures that a root trace id exists by generating one if None.
        Return self to allow for chaining.
        """
        if self._root is None:
            self._root = TraceId().to_id()
        return self

    @property
    def root(self):
        """
        Return trace id of the header
        """
        return self._root

    @property
    def parent(self):
        """
        Return the parent segment id in the header
        """
        return self._parent

    @property
    def sampled(self):
        """
        Return the sampling decision in the header.
        It's 0 or 1 or '?'.
        """
        return self._sampled

    @property
    def lineage(self):
        """
        Return the lineage in the header
        """
        return self._lineage

    @property
    def data(self):
        """
        Return the arbitrary fields in the trace header.
        """
        return self._data
