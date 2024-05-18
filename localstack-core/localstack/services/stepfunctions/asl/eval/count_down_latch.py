import threading


class CountDownLatch:
    # TODO: add timeout support.
    def __init__(self, num: int):
        self._num: int = num
        self.lock = threading.Condition()

    def count_down(self) -> None:
        self.lock.acquire()
        self._num -= 1
        if self._num <= 0:
            self.lock.notify_all()
        self.lock.release()

    def wait(self) -> None:
        self.lock.acquire()
        while self._num > 0:
            self.lock.wait()
        self.lock.release()
