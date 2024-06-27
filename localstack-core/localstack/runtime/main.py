"""This is the entrypoint used to start the localstack runtime. It starts the infrastructure and also
manages the interaction with the operating system - mostly signal handlers for now."""

import signal
import sys
import traceback

from localstack import config, constants
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


def print_runtime_information(in_docker: bool = False):
    # FIXME: this is legacy code from the old CLI, reconcile with new CLI and runtime output
    from localstack.utils.container_networking import get_main_container_name
    from localstack.utils.container_utils.container_client import ContainerException
    from localstack.utils.docker_utils import DOCKER_CLIENT

    print()
    print(f"LocalStack version: {constants.VERSION}")
    if in_docker:
        try:
            container_name = get_main_container_name()
            print("LocalStack Docker container name: %s" % container_name)
            inspect_result = DOCKER_CLIENT.inspect_container(container_name)
            container_id = inspect_result["Id"]
            print("LocalStack Docker container id: %s" % container_id[:12])
            image_details = DOCKER_CLIENT.inspect_image(inspect_result["Image"])
            digests = image_details.get("RepoDigests") or ["Unavailable"]
            print("LocalStack Docker image sha: %s" % digests[0])
        except ContainerException:
            print(
                "LocalStack Docker container info: Failed to inspect the LocalStack docker container. "
                "This is likely because the docker socket was not mounted into the container. "
                "Without access to the docker socket, LocalStack will not function properly. Please "
                "consult the LocalStack documentation on how to correctly start up LocalStack. ",
                end="",
            )
            if config.DEBUG:
                print("Docker debug information:")
                traceback.print_exc()
            else:
                print(
                    "You can run LocalStack with `DEBUG=1` to get more information about the error."
                )

    if config.LOCALSTACK_BUILD_DATE:
        print("LocalStack build date: %s" % config.LOCALSTACK_BUILD_DATE)

    if config.LOCALSTACK_BUILD_GIT_HASH:
        print("LocalStack build git hash: %s" % config.LOCALSTACK_BUILD_GIT_HASH)

    print()


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
        sys.stdout.write(f"Localstack returning with exit code {e.code}. Reason: {e}")
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
