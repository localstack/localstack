"""
System-wide patches that should be applied.
"""

from localstack.runtime import hooks
from localstack.utils.patch import patch


def patch_thread_pool():
    """
    This patch to ThreadPoolExecutor makes the executor remove the threads it creates from the global
    ``_thread_queues`` of ``concurrent.futures.thread``, which joins all created threads at python exit and
    will block interpreter shutdown if any threads are still running, even if they are daemon threads.
    """

    import concurrent.futures.thread

    @patch(concurrent.futures.thread.ThreadPoolExecutor._adjust_thread_count)
    def _adjust_thread_count(fn, self) -> None:
        fn(self)

        for t in self._threads:
            if not t.daemon:
                continue
            try:
                del concurrent.futures.thread._threads_queues[t]
            except KeyError:
                pass


def patch_urllib3_connection_pool(**constructor_kwargs):
    """
    Override the default parameters of HTTPConnectionPool, e.g., set the pool size via maxsize=16
    """
    try:
        from urllib3 import connectionpool, poolmanager

        class MyHTTPSConnectionPool(connectionpool.HTTPSConnectionPool):
            def __init__(self, *args, **kwargs):
                kwargs.update(constructor_kwargs)
                super(MyHTTPSConnectionPool, self).__init__(*args, **kwargs)

        poolmanager.pool_classes_by_scheme["https"] = MyHTTPSConnectionPool

        class MyHTTPConnectionPool(connectionpool.HTTPConnectionPool):
            def __init__(self, *args, **kwargs):
                kwargs.update(constructor_kwargs)
                super(MyHTTPConnectionPool, self).__init__(*args, **kwargs)

        poolmanager.pool_classes_by_scheme["http"] = MyHTTPConnectionPool
    except Exception:
        pass


_applied = False


@hooks.on_runtime_start(priority=100)  # apply patches earlier than other hooks
def apply_runtime_patches():
    # FIXME: find a better way to apply system-wide patches
    global _applied
    if _applied:
        return
    _applied = True

    from localstack.http.duplex_socket import enable_duplex_socket

    patch_urllib3_connection_pool(maxsize=128)
    patch_thread_pool()
    enable_duplex_socket()
