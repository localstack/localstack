import threading

from localstack.utils.scaling import StoppableThread, ThreadScaler
from localstack.utils.sync import retry


class SimpleStoppableThread(StoppableThread):
    def __init__(self, start_callback, stop_callback):
        super().__init__()
        self.stop_event = threading.Event()
        self.start_callback = start_callback
        self.stop_callback = stop_callback

    def run(self):
        self.start_callback()
        self.stop_event.wait()

    def stop(self):
        self.stop_callback()
        self.stop_event.set()


class SimpleThreadScaler(ThreadScaler):
    def __init__(self, start_callback, stop_callback):
        super().__init__()
        self.start_callback = start_callback
        self.stop_callback = stop_callback

    def create_thread(self) -> StoppableThread:
        return SimpleStoppableThread(self.start_callback, self.stop_callback)


class TestThreadScaling:
    def test_scale_up(self):
        total_threads = 5
        counter_lock = threading.Lock()
        calls = 0

        def _callback():
            nonlocal calls
            with counter_lock:
                calls += 1

        scaler = SimpleThreadScaler(_callback, _callback)
        scaler.scale_to(total_threads)

        def _test_calls():
            assert calls == total_threads

        retry(_test_calls, sleep=0.1)
        assert scaler.running_workers() == total_threads
        scaler.stop()
        scaler.wait_for_stopped_threads()
        assert scaler.running_workers() == 0

    def test_scale_down(self):
        counter_lock = threading.Lock()
        start_calls = 0
        stop_calls = 0

        def _start_callback():
            nonlocal start_calls
            with counter_lock:
                start_calls += 1

        def _stop_callback():
            nonlocal stop_calls
            with counter_lock:
                stop_calls += 1

        scaler = SimpleThreadScaler(_start_callback, _stop_callback)
        scaler.scale_to(5)

        def _test_start_calls(target_calls):
            assert start_calls == target_calls

        retry(_test_start_calls, sleep=0.1, target_calls=5)

        scaler.scale_to(2)

        def _test_stop_calls(target_calls):
            assert stop_calls == target_calls

        retry(_test_stop_calls, sleep=0.1, target_calls=3)

        scaler.stop()
        scaler.wait_for_stopped_threads()
