import inspect
import json
import sys
import threading
import traceback

import psutil
import pytest


@pytest.hookimpl(trylast=True)
def pytest_unconfigure(config):
    print(
        f"Still running threads after pytest unconfigure: {threading.enumerate()}, Count: {threading.active_count()}"
    )
    thread_frames = [
        (sys._current_frames().get(thread.ident), thread) for thread in threading.enumerate()
    ]
    info_tuples = [
        {
            "file_name": frame.f_code.co_filename,
            "function_name": frame.f_code.co_name,
            "line_no": frame.f_code.co_firstlineno,
            "frame_traceback": traceback.format_stack(frame),
            "thread_name": thread.name,
            "thread_target": repr(thread._target) if hasattr(thread, "_target") else None,
            "thread_target_file": inspect.getfile(thread._target)
            if hasattr(thread, "_target") and thread._target
            else None,
        }
        for frame, thread in thread_frames
        if frame
    ]
    print(f"Thread actions: {json.dumps(info_tuples, indent=None)}")
    current_process = psutil.Process()
    children = current_process.children(recursive=True)

    process_information_list = []

    for child in children:
        try:
            process_information_list.append(
                {"cmdline": child.cmdline(), "pid": child.pid, "status": child.status()}
            )
        except Exception as e:
            print(f"Error while collecting process information of {child.pid}: {e}")

    print(f"Subprocesses: {json.dumps(process_information_list, indent=None)}")
