# DEPRECATED: use localstack.utils.asyncio
from .asyncio import (  # noqa
    EVENT_LOOPS,
    THREAD_POOL,
    AdaptiveThreadPool,
    AsyncThread,
    ensure_event_loop,
    get_main_event_loop,
    get_named_event_loop,
    receive_from_queue,
    run_coroutine,
    run_sync,
)
