import threading

from localstack.utils.threads import (
    TMP_THREADS,
    FuncThread,
    cleanup_threads_and_processes,
    start_thread,
    start_worker_thread,
)


class TestThreads:
    class TestStartThread:
        def test_start_thread_returns_a_func_thread(self):
            def examplefunc(*args):
                pass

            thread = start_thread(examplefunc)

            assert isinstance(thread, FuncThread)
            assert thread.name.startswith("examplefunc-")
            assert thread in TMP_THREADS

        def test_start_thread_with_custom_name(self):
            thread = start_thread(lambda: None, name="somefunc")

            assert thread.name.startswith("somefunc-")

    class TestStartWorkerThread:
        def test_start_worker_thread_returns_a_func_thread(self):
            thread = start_worker_thread(lambda: None)

            assert isinstance(thread, FuncThread)
            assert thread.name.startswith("start_worker_thread-")
            assert thread not in TMP_THREADS

        def test_start_worker_thread_with_custom_name(self):
            thread = start_worker_thread(lambda: None, name="somefunc")
            assert thread.name.startswith("somefunc-")

    def test_cleanup_threads_and_processes_calls_shutdown_hooks(self):
        started = threading.Event()
        done = threading.Event()

        # Note: we're extending FuncThread here to make sure we have access to `_stop_event`
        # Regular users would use `start_thread` instead
        class ThreadTest(FuncThread):
            def __init__(self) -> None:
                super().__init__(self.run_method)

            def run_method(self, *args):
                started.set()
                # thread waits until it is stopped
                self._stop_event.wait()
                done.set()

        test_thread = ThreadTest()
        TMP_THREADS.append(test_thread)
        test_thread.start()
        assert started.wait(timeout=2)
        cleanup_threads_and_processes()
        assert done.wait(timeout=2)
