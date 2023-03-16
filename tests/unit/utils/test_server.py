import threading
from queue import Queue

from localstack.utils.serving import Server


def test_server_startup_thread_running(cleanups):
    """Test that is_running() can be used in the server thread's do_run() method"""

    queue = Queue()
    event = threading.Event()

    class TestServer(Server):
        def do_run(self):
            queue.put(self.is_running())
            event.set()

        def do_start_thread(self):
            try:
                return super().do_start_thread()
            finally:
                # return from this function after the server thread has already started in do_run(),
                # to simulate a potential race condition and ensure self.is_running() returns True
                event.wait(1)

    # start server
    server = TestServer(0)
    server.start()
    cleanups.append(lambda: server.shutdown())

    # assert that is_running() is True in the thread method
    is_running = queue.get()
    assert is_running
