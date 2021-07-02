import cProfile
import logging
import pstats
import threading
import traceback
from functools import wraps

from localstack.constants import LOCALSTACK_ROOT_FOLDER

# set up logger
LOG = logging.getLogger(__name__)

PROFILED_METHODS = [
    # TODO activate as needed
    # (str, 'lower'),
    # (str, 'rpartition', False),
    # (_io.BufferedReader, 'readline', True)
]


def profiled(lines=50):
    """Function decorator that profiles code execution."""
    # return profiled_via_yappi(lines)
    return profiled_via_cprofile(lines)


def profiled_via_cprofile(lines=50):
    skipped_lines = ["site-packages", "lib/python"]
    Thread = threading.Thread
    method_invocations = {}

    for m_entry in PROFILED_METHODS:

        def _patch(entry):
            m_obj = getattr(entry[0], entry[1])
            m_str = str(m_obj)
            method_invocations[m_str] = {"__count__": 0}

            def m_patched(*args, **kwargs):
                entry = method_invocations[m_str]
                stack = traceback.format_stack()
                last_frame = str(stack[-2]).strip()
                entry[last_frame] = entry.get(last_frame, 0) + 1
                if entry["__count__"] % 1000 == 0:
                    # TODO print(''.join(stack))
                    pass
                entry["__count__"] += 1
                return m_obj(*args, **kwargs)

            try:
                from forbiddenfruit import curse

                curse(entry[0], entry[1], m_patched)
            except Exception as e:
                print("Unable to set attr:", entry[0], entry[1], m_patched, e)

        _patch(m_entry)

    def add_stats(prof):
        if Thread.stats is None:
            Thread.stats = pstats.Stats(prof)
        else:
            Thread.stats.add(prof)

    def enable_thread_profiling():
        if getattr(Thread, "_profiling_patched", None):
            return
        setattr(Thread, "_profiling_patched", True)
        Thread.stats = None
        thread_run = Thread.run

        def profile_run(self):
            self._prof = cProfile.Profile()
            self._prof.enable()
            thread_run(self)
            self._prof.disable()
            add_stats(self._prof)

        Thread.run = profile_run

    def profile_current_thread(close_profile=None):
        if close_profile:
            close_profile.disable()
            add_stats(close_profile)
            return
        prof = cProfile.Profile()
        prof.enable()
        return prof

    def get_thread_stats():
        stats = getattr(Thread, "stats", None)
        if stats is None:
            LOG.warning("Thread profiling was not enabled, or no threads finished running.")
        return stats

    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            enable_thread_profiling()
            prof_this_thread = profile_current_thread()
            try:
                return f(*args, **kwargs)
            finally:
                profile_current_thread(prof_this_thread)
                result = get_thread_stats()
                list_orig = result.fcn_list
                for sort in ("tottime", "cumulative", "ncalls"):
                    result.fcn_list = list_orig
                    result.sort_stats(sort)
                    result.fcn_list = [
                        e for e in result.fcn_list if not any([s in str(e) for s in skipped_lines])
                    ]
                    result.print_stats(lines)

        return wrapped

    return wrapper


def profiled_via_yappi(lines=50):
    skipped_lines = ["site-packages", "lib/python"]
    skipped_lines = []

    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            import yappi

            yappi.start()
            try:
                return f(*args, **kwargs)
            finally:
                result = list(yappi.get_func_stats())
                yappi.stop()
                yappi.clear_stats()
                result = [r for r in result if all([s not in r.full_name for s in skipped_lines])]
                entries = result[:lines]
                prefix = LOCALSTACK_ROOT_FOLDER
                result = []
                result.append("ncall\tttot\ttsub\ttavg\tname")

                def c(num):
                    return str(num)[:7]

                for e in entries:
                    name = e.full_name.replace(prefix, "")
                    result.append(
                        "%s\t%s\t%s\t%s\t%s" % (c(e.ncall), c(e.ttot), c(e.tsub), c(e.tavg), name)
                    )
                result = "\n".join(result)
                print(result)

        return wrapped

    return wrapper


def log_duration(name=None):
    """Function decorator to log the duration of function invocations."""

    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            from localstack.utils.common import now_utc

            start_time = now_utc(millis=True)
            try:
                return f(*args, **kwargs)
            finally:
                end_time = now_utc(millis=True)
                func_name = name or f.__name__
                duration = end_time - start_time
                if duration > 500:
                    LOG.info('Execution of "%s" took %.2fms', func_name, duration)

        return wrapped

    return wrapper
