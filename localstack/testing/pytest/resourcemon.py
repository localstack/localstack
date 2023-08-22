"""
ResourceMon is a resource monitor that keeps track of resource usage during a
pipeline run.

We use this to track the memory usage (initially) of the runner instance to
know when it is out of memory.
"""
import json
import time
from typing import Optional, Tuple

import psutil
import pytest


class ResourceMonitorPlugin:
    def __init__(self):
        self.logfile_path = "./resource_usage.log"
        self.logfile = None

    @pytest.hookimpl()
    def pytest_collectstart(self, collector: pytest.Collector):
        self.logfile = open(self.logfile_path, "w")
        self.capture("start")

    @pytest.hookimpl()
    def pytest_runtest_logfinish(self, nodeid: str, location: Tuple[str, Optional[int], str]):
        if self.logfile is None:
            return

        filename, line_no, testname = location
        self.capture("post-test", nodeid, filename, line_no, testname)

    @pytest.hookimpl()
    def pytest_terminal_summary(self, *args, **kwargs):
        if self.logfile is None:
            return
        self.logfile.close()

    def capture(
        self,
        label: str,
        node_id: str | None = None,
        filename: str | None = None,
        line_no: int | None = None,
        testname: str | None = None,
    ):
        memory_usage = psutil.virtual_memory()
        row = {
            "time": time.time(),
            "used": memory_usage.used,
            "available": memory_usage.available,
            "node_id": node_id,
            "filename": filename,
            "line_no": line_no,
            "testname": testname,
            "label": label,
        }

        self.print_row(row)

    def print_row(self, row: dict):
        if self.logfile is None:
            return
        line = json.dumps(row)
        print(line, file=self.logfile)
        self.logfile.flush()
