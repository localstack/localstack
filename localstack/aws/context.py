import threading
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Generic, List, Optional, TypeVar

from localstack.utils.patch import patch

if TYPE_CHECKING:
    # make sure this is free from localstack runtime imports to avoid circular imports
    from localstack.aws.api import RequestContext

_T = TypeVar("_T")


class _ThreadLocalStack(threading.local, Generic[_T]):
    """
    A simple generic stack that is thread local.
    """

    stack: List[_T]

    def __init__(self):
        self.stack = []

    def push(self, value: _T):
        self.stack.append(value)

    def pop(self) -> _T:
        return self.stack.pop()

    def head(self) -> Optional[_T]:
        try:
            return self.stack[-1]
        except IndexError:
            return None


class NoContextError(ValueError):
    pass


request_stack: _ThreadLocalStack["RequestContext"] = _ThreadLocalStack()


def current_request_context() -> "RequestContext":
    """
    Returns the current context in the request context stack populated by the ``LocalstackAwsGateway``.

    :returns: the current request context
    :raises NoContextError: if there is no RequestContext on the stack
    """
    context = request_stack.head()
    if not context:
        raise NoContextError("Not operating within in a request context")
    return context


class _QueueWrapper:
    def __init__(self, queue):
        self.queue = queue

    def put(self, item, *args, **kwargs):
        ContextAwareThreadPoolExecutor._patch_work_item(item)
        self.queue.put(item, *args, **kwargs)

    def put_nowait(self, item, *args, **kwargs):
        ContextAwareThreadPoolExecutor._patch_work_item(item)
        self.queue.put_nowait(item, *args, **kwargs)

    def get_nowait(self, *args, **kwargs):
        return self.queue.get_nowait(*args, **kwargs)

    def get(self, *args, **kwargs):
        return self.queue.get(*args, **kwargs)

    def qsize(self, *args, **kwargs):
        return self.queue.qsize(*args, **kwargs)

    def empty(self, *args, **kwargs):
        return self.queue.empty(*args, **kwargs)


class ContextAwareThreadPoolExecutor(ThreadPoolExecutor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._work_queue = _QueueWrapper(self._work_queue)

    @staticmethod
    def _patch_work_item(item):
        if item is None:
            return
        item._context = request_stack.head()

        @patch(item.run)
        def WorkItem_run(self_, run):
            # push context back to the thread local
            if self_._context:
                request_stack.push(self_._context)
            try:
                return run()
            finally:
                request_stack.pop()
