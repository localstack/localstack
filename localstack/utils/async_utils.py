import time
import asyncio
import concurrent.futures
from contextvars import copy_context
from localstack.utils import common
from localstack.utils.common import FuncThread, TMP_THREADS

# Thread pool executor for running sync functions in async context.
# Note: For certain APIs like DynamoDB, we need 3x threads for each parallel request,
# as during request processing the API calls out to the DynamoDB API again (recursively).
# (TODO: This could potentially be improved if we move entirely to asyncio functions.)
THREAD_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=300)
TMP_THREADS.append(THREAD_POOL)

# reference to named event loop instances
EVENT_LOOPS = {}


class AsyncThread(FuncThread):

    def __init__(self, async_func_gen=None, loop=None):
        """ Pass a function that receives an event loop instance and a shutdown event,
            and returns an async function. """
        FuncThread.__init__(self, self.run_func, None)
        self.async_func_gen = async_func_gen
        self.loop = loop
        self.shutdown_event = None

    def run_func(self, *args):
        loop = self.loop or ensure_event_loop()
        self.shutdown_event = asyncio.Event()
        if self.async_func_gen:
            async_func = self.async_func_gen(loop, self.shutdown_event)
            if async_func:
                loop.run_until_complete(async_func)
        loop.run_forever()

    def stop(self, quiet=None):
        if self.shutdown_event:
            self.shutdown_event.set()
            self.shutdown_event = None

    @classmethod
    def run_async(cls, func=None, loop=None):
        thread = AsyncThread(func, loop=loop)
        thread.start()
        TMP_THREADS.append(thread)
        return thread


async def run_sync(func, *args, thread_pool=None):
    loop = asyncio.get_running_loop()
    thread_pool = thread_pool or THREAD_POOL
    return await loop.run_in_executor(thread_pool, copy_context().run, func, *args)


def ensure_event_loop():
    try:
        return asyncio.get_event_loop()
    except Exception:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop


def get_named_event_loop(name):
    result = EVENT_LOOPS.get(name)
    if result:
        return result

    def async_func_gen(loop, shutdown_event):
        EVENT_LOOPS[name] = loop

    AsyncThread.run_async(async_func_gen)
    time.sleep(1)
    return EVENT_LOOPS[name]


async def receive_from_queue(queue):
    def get():
        # run in a retry loop (instead of blocking forever) to allow for graceful shutdown
        while True:
            try:
                if common.INFRA_STOPPED:
                    return
                return queue.get(timeout=1)
            except Exception:
                pass

    msg = await run_sync(get)
    return msg
