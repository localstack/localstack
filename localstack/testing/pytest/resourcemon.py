"""
ResourceMon is a resource monitor that keeps track of resource usage during a
pipeline run.

We use this to track the memory usage (initially) of the runner instance to
know when it is out of memory.
"""
import json
import sys
import time
from abc import ABC, abstractclassmethod
from dataclasses import asdict, dataclass
from typing import Optional, Tuple

import psutil
import pytest


@dataclass
class Serializable:
    def to_dict(self):
        return asdict(self)


class FromPsutil(ABC):
    @abstractclassmethod
    def from_psutil(cls, result):
        pass


@dataclass
class Memory(Serializable, FromPsutil):
    total: int
    available: int
    percent: float
    used: int
    free: int
    active: int

    @classmethod
    def from_psutil(cls, result):
        return cls(
            total=result.total,
            available=result.available,
            percent=result.percent,
            used=result.used,
            free=result.free,
            active=result.active,
        )


@dataclass
class Swap(Serializable, FromPsutil):
    total: int
    used: int
    free: int
    percent: float

    @classmethod
    def from_psutil(cls, result):
        return cls(
            total=result.total,
            used=result.used,
            free=result.free,
            percent=result.percent,
        )


@dataclass
class Disk(Serializable, FromPsutil):
    total: int
    used: int
    free: int
    percent: float

    @classmethod
    def from_psutil(cls, result):
        return cls(
            total=result.total,
            used=result.used,
            free=result.free,
            percent=result.percent,
        )


class ResourceMonitorPlugin:
    @pytest.hookimpl()
    def pytest_collectstart(self, collector: pytest.Collector):
        self.capture("start")

    @pytest.hookimpl()
    def pytest_runtest_logfinish(self, nodeid: str, location: Tuple[str, Optional[int], str]):
        filename, line_no, testname = location
        try:
            self.capture("post-test", nodeid, filename, line_no, testname)
        except Exception as e:
            print(f"Error capturing statistics: {e}", file=sys.stderr)

    @pytest.hookimpl()
    def pytest_terminal_summary(self, *args, **kwargs):
        pass

    def capture(
        self,
        label: str,
        node_id: str | None = None,
        filename: str | None = None,
        line_no: int | None = None,
        testname: str | None = None,
    ):
        memory_usage = Memory.from_psutil(psutil.virtual_memory())
        loadavg = psutil.getloadavg()
        cpu_percents = psutil.cpu_percent()
        swap = Swap.from_psutil(psutil.swap_memory())
        disk = Disk.from_psutil(psutil.disk_usage("/"))
        row = {
            "time": time.time(),
            "memory": memory_usage.to_dict(),
            "node_id": node_id,
            "filename": filename,
            "line_no": line_no,
            "testname": testname,
            "label": label,
            "loadavg": loadavg,
            "cpu_percents": cpu_percents,
            "swap": swap.to_dict(),
            "disk": disk.to_dict(),
        }

        self.print_row(row)

    def print_row(self, row: dict):
        print(f"*** RESOURCE USAGE:{json.dumps(row)}")
