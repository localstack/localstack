from __future__ import annotations

import logging
from collections import defaultdict
from typing import Generator

from _pytest.reports import TestReport
from _pytest.terminal import TerminalReporter

from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.http import Response

LOG = logging.getLogger(__name__)
METHOD_PAIRS = {
    "kms": {
        "create": [
            "CreateKey",
            "ReplicateKey",
            "CancelKeyDeletion",
        ],
        "delete": [
            "ScheduleKeyDeletion",
        ],
    },
    "dynamodb": {
        "create": ["CreateTable"],
        "delete": ["DeleteTable"],
    },
    "kinesis": {
        "create": ["CreateStream"],
        "delete": ["DeleteStream"],
    },
    "opensearch": {
        "create": ["CreateDomain"],
        "delete": ["DeleteDomain"],
    },
    "cloudformation": {
        "create": ["CreateStack", "CreateChangeSet"],
        "delete": ["DeleteStack", "DeleteChangeSet"],
    },
    "s3": {
        "create": ["CreateBucket"],
        "delete": ["DeleteBucket"],
    },
    "sns": {
        "create": ["CreateTopic"],
        "delete": ["DeleteTopic"],
    },
    "stepfunctions": {
        "create": ["CreateStateMachine"],
        "delete": ["DeleteStateMachine"],
    },
}

# TODO: unify this with the type in the pytest plugin
TestKey = str

# service, operation, status code
Call = tuple[str, str, int]


class TestResourceLifetimesCapture:
    """
    Captures traces of resources by test name to determine resources that are left over at the
    end of a test
    """

    # TODO: what if there are multiple calls to create the same resource in the same test?
    results: dict[TestKey, list[Call]]
    current_test_key: TestKey | None

    def __init__(self):
        self.results = defaultdict(list)
        self.current_test_key = None
        self.last_report = TestReport

    def set_test(self, test_key: TestKey):
        self.current_test_key = test_key

    def end_test(self):
        # only capture successful tests, since we expect the test suite to completely pass,
        # and failed tests may leave some state around

        # TODO: perhaps these failed tests are leaking resources,
        # and it would be worth capturing the result?
        # TODO: what about repeated tests? The pro tests retry 3 times
        if not self.last_report.passed:
            self.results.pop(self.current_test_key, None)

        self.current_test_key = None

    def terminal_report(self, reporter: TerminalReporter):
        """
        Method used to present information to the reporter class
        """
        lines = list(self._extract_leaky_report_lines())
        if not lines:
            # nothing to say!
            return

        reporter.section("Leaky tests", red=True)
        for line in lines:
            reporter.write_line(line)

    def _extract_leaky_report_lines(self) -> Generator[str, None, None]:
        for tests_key, api_calls in self.results.items():
            services = set(service for (service, operation, _) in api_calls)
            for tested_service in services:
                if tested_service not in METHOD_PAIRS:
                    continue

                called_methods = [
                    (service, operation)
                    for (service, operation, status_code) in api_calls
                    if service == tested_service and status_code < 400
                ]

                service_methods = METHOD_PAIRS[tested_service]

                created_score = len(
                    [
                        method
                        for (_, method) in called_methods
                        if method in service_methods["create"]
                    ]
                )
                deleted_score = len(
                    [
                        method
                        for (_, method) in called_methods
                        if method in service_methods["delete"]
                    ]
                )

                if created_score == deleted_score:
                    continue

                # special cases

                # cloudformation: DeleteStack is idempotent, so it may be called multiple times.
                if tested_service == "cloudformation" and created_score < deleted_score:
                    continue

                outcome = (
                    "not enough deletes" if created_score > deleted_score else "too many deletes"
                )
                operations = [operation for (_, operation) in called_methods]
                yield f"test {tests_key}; service {tested_service}; operations {operations}; {outcome=}"

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not context.service or not context.operation:
            return

        service = context.service.service_name
        operation = context.operation.name

        # not in a test context
        if self.current_test_key is None:
            return

        self.results[self.current_test_key].append((service, operation, response.status_code))
