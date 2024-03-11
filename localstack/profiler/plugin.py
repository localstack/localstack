from localstack.runtime import hooks
from localstack import config


@hooks.on_infra_start()
def start_profiling():
    if not config.ENABLE_PROFILING:
        return

    from localstack.profiler.start import start_profiling

    start_profiling()


@hooks.on_infra_shutdown()
def stop_profiling():
    if not config.ENABLE_PROFILING:
        return

    from localstack.profiler.start import stop_profiling

    stop_profiling()
