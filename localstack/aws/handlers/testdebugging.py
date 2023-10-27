from __future__ import annotations

import json
import logging
import sqlite3
from collections import defaultdict
from pathlib import Path

from _pytest.reports import TestReport

from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.http import Response

LOG = logging.getLogger(__name__)

# TODO: unify this with the type in the pytest plugin
TestKey = str

# service, operation, status code
Call = tuple[str, str, int]


class Database:
    def __init__(self, output_path: Path | str):
        self.conn = sqlite3.connect(output_path)
        self.initialise()

    def initialise(self):
        with self.conn as conn:
            conn.execute("drop table if exists api_calls")
            conn.execute(
                """
            create table api_calls (
                id integer primary key,
                test_key text not null,
                api_calls text not null
                )
                """
            )

    def add(self, test_key: TestKey, api_calls: list[Call]):
        with self.conn as conn:
            conn.execute(
                "insert into api_calls (test_key, api_calls) values (?, ?)",
                (test_key, json.dumps(api_calls)),
            )


class TestResourceLifetimesCapture:
    """
    Captures traces of resources by test name to determine resources that are left over at the
    end of a test
    """

    db: Database
    # TODO: what if there are multiple calls to create the same resource in the same test?
    results: dict[TestKey, list[Call]]
    current_test_key: TestKey | None

    def __init__(self, output_path: Path | str):
        self.db = Database(output_path)
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
        if self.last_report.passed:
            self.commit()
        self.current_test_key = None

    def commit(self):
        if not self.current_test_key:
            # XXX this can not happen, but this makes the typechecker happy
            return
        self.db.add(self.current_test_key, self.results[self.current_test_key])

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not context.service or not context.operation:
            return

        service = context.service.service_name
        operation = context.operation.name

        # not in a test context
        if self.current_test_key is None:
            return

        self.results[self.current_test_key].append((service, operation, response.status_code))
