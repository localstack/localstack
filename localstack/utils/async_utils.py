import time
import asyncio
import concurrent.futures
from contextvars import copy_context
from localstack.utils import common
from localstack.utils.common import FuncThread, TMP_THREADS

# thread pool executor for running sync functions in async context
THREAD_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=30)
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

    def run_func(self, *args):
        loop = self.loop or ensure_event_loop()
        self.shutdown_event = asyncio.Event()
        if self.async_func_gen:
            async_func = self.async_func_gen(loop, self.shutdown_event)
            if async_func:
                loop.run_until_complete(async_func)
        loop.run_forever()

    def stop(self, quiet=None):
        self.shutdown_event.set()

    @classmethod
    def run_async(cls, func=None, loop=None):
        thread = AsyncThread(func, loop=loop)
        thread.start()
        TMP_THREADS.append(thread)
        return thread


async def run_sync(func, *args):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(THREAD_POOL, copy_context().run, func, *args)


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
