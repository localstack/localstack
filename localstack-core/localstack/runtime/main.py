"""This is the entrypoint used to start the localstack runtime. It starts the infrastructure and also
manages the interaction with the operating system - mostly signal handlers for now."""

import signal
import sys

from localstack import config
from localstack.runtime.exceptions import LocalstackExit


def main_legacy():
    from localstack.services import infra

    # signal handler to make sure SIGTERM properly shuts down localstack
    def _terminate_localstack(sig: int, frame):
        infra.exit_infra(0)

    # SIGINT is currently managed implicitly in start_infra via `except KeyboardInterrupt`
    signal.signal(signal.SIGTERM, _terminate_localstack)

    try:
        infra.start_infra(asynchronous=False)
    except LocalstackExit as e:
        sys.exit(e.code)

    sys.exit(infra.EXIT_CODE.get())


def print_runtime_information():
    # FIXME: refactor legacy code
    from localstack.services.infra import print_runtime_information

    print_runtime_information()


def main_v2():
    from localstack.logging.setup import setup_logging_from_config
    from localstack.runtime import current

    try:
        setup_logging_from_config()
        runtime = current.initialize_runtime()
    except Exception as e:
        sys.stdout.write(f"ERROR: The LocalStack Runtime could not be initialized: {e}\n")
        sys.stdout.flush()
        raise

    # TODO: where should this go?
    print_runtime_information()

    # signal handler to make sure SIGTERM properly shuts down localstack
    def _terminate_localstack(sig: int, frame):
        sys.stdout.write(f"Localstack runtime received signal {sig}\n")
        sys.stdout.flush()
        runtime.exit(0)

    signal.signal(signal.SIGINT, _terminate_localstack)
    signal.signal(signal.SIGTERM, _terminate_localstack)

    try:
        runtime.run()
    except LocalstackExit as e:
        sys.exit(e.code)
    except Exception as e:
        sys.stdout.write(f"ERROR: the LocalStack runtime exited unexpectedly: {e}\n")
        sys.stdout.flush()
        raise

    sys.exit(runtime.exit_code)


def main():
    if config.LEGACY_RUNTIME:
        main_legacy()
    else:
        main_v2()


if __name__ == "__main__":
    main()
