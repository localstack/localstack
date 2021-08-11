"""
Command line interface (CLI) for LocalStack.

Usage:
  localstack [options] <command> [ <args> ... ]
  localstack (-v | --version)
  localstack (-h | --help)

Commands:%s

Options:
  -d --debug                  Show verbose debug output
  -h --help                   Show this screen
  -v --version                Show version
%s
"""

import logging
import os
import sys
import traceback

from docopt import docopt

from localstack import config, constants
from localstack.utils import bootstrap
from localstack.utils.bootstrap import (
    get_docker_image_details,
    get_main_container_id,
    get_main_container_ip,
    get_main_container_name,
    get_server_version,
    setup_logging,
    start_infra_in_docker,
    start_infra_locally,
    validate_localstack_config,
)
from localstack.utils.docker import DOCKER_CLIENT
from localstack.utils.run import run

# Note: make sure we don't have other imports at the root level here

# set up logger
LOG = logging.getLogger(__name__)


def cmd_infra(argv, args):
    """
    Usage:
      localstack infra <subcommand> [options]

    Commands:
      infra start       Start the local infrastructure

    Options:
      --docker          Run the infrastructure in a Docker container (default)
      --host            Run the infrastructure on the local host (deprecated / not supported)
    """
    if argv[0] == "start":
        argv = ["infra", "start"] + argv[1:]
        args["<command>"] = "infra"
        args["<args>"] = ["start"] + args["<args>"]
    args.update(docopt(cmd_infra.__doc__.strip(), argv=argv))
    if args["<subcommand>"] == "start":
        if args["--docker"] and args["--host"]:
            raise Exception("Please specify either --docker or --host")
        print("Starting local dev environment. CTRL-C to quit.")
        in_docker = args["--docker"] or not args["--host"]
        if in_docker:
            start_infra_in_docker()
        else:
            start_infra_locally()


def cmd_config(argv, args):
    """
    Usage:
      localstack config <subcommand> [options]

    Commands:
      config validate       Validate local configurations (e.g. docker-compose)

    Options:
      --file=<>          Use custom docker compose file (default: docker-compose.yml)
    """
    args.update(docopt(cmd_config.__doc__.strip(), argv=argv))

    if args["<subcommand>"] == "validate":
        docker_compose_file_name = args.get("--file") or "docker-compose.yml"
        validate_localstack_config(docker_compose_file_name)
    else:
        raise Exception("Please specify a valid command")


def cmd_ssh(argv, args):
    """
    Usage:
      localstack ssh [options]

    Commands:
      ssh               Obtain a shell in the running LocalStack container

    Options:
    """
    args.update(docopt(cmd_ssh.__doc__.strip(), argv=argv))
    if not DOCKER_CLIENT.is_container_running(config.MAIN_CONTAINER_NAME):
        raise Exception(
            'Expected 1 running "%s" container, but found none' % config.MAIN_CONTAINER_NAME
        )
    try:
        process = run("docker exec -it %s bash" % config.MAIN_CONTAINER_NAME, tty=True)
        process.wait()
    except KeyboardInterrupt:
        pass


def cmd_status(argv, args):
    """
    Usage:
      localstack status
    """
    args.update(docopt(cmd_status.__doc__.strip(), argv=argv))
    print_status()


def print_status():
    print("Base version:\t\t%s" % get_server_version())
    img = get_docker_image_details()
    print("Docker image:\t\tTag %s, ID %s, Created %s" % (img["tag"], img["id"], img["created"]))
    cont_name = config.MAIN_CONTAINER_NAME
    running = DOCKER_CLIENT.is_container_running(cont_name)
    cont_status = "stopped"
    if running:
        cont_status = 'running (name: "%s", IP: %s)' % (
            get_main_container_name(),
            get_main_container_ip(),
        )
    print("Container status:\t%s" % cont_status)


def print_version(in_docker=False):
    print()
    print("LocalStack version: %s" % constants.VERSION)
    if in_docker:
        id = get_main_container_id()
        if id:
            print("LocalStack Docker container id: %s" % id[:12])

    if config.LOCALSTACK_BUILD_DATE:
        print("LocalStack build date: %s" % config.LOCALSTACK_BUILD_DATE)

    if config.LOCALSTACK_BUILD_GIT_HASH:
        print("LocalStack build git hash: %s" % config.LOCALSTACK_BUILD_GIT_HASH)

    print()


def main():
    LOG.info("LocalStack version: %s" % constants.VERSION)
    # set basic CLI commands
    config.CLI_COMMANDS["infra"] = {
        "description": "Commands to manage the infrastructure",
        "function": cmd_infra,
    }
    config.CLI_COMMANDS["start"] = {
        "description": "Shorthand to start the infrastructure",
        "function": cmd_infra,
    }
    config.CLI_COMMANDS["ssh"] = {
        "description": "Shorthand to obtain a shell in the running container",
        "function": cmd_ssh,
    }
    config.CLI_COMMANDS["status"] = {
        "description": "Obtain status details about the installation",
        "function": cmd_status,
    }
    config.CLI_COMMANDS["config"] = {
        "description": "Validate docker configurations",
        "function": cmd_config,
    }

    # load CLI plugins
    bootstrap.load_plugins(scope=bootstrap.PLUGIN_SCOPE_COMMANDS)

    # create final usage string
    additional_params = []
    additional_commands = ""
    for cmd in sorted(config.CLI_COMMANDS.keys()):
        cmd_details = config.CLI_COMMANDS[cmd]
        additional_commands += "\n  %s%s%s" % (
            cmd,
            (20 - len(cmd)) * " ",
            cmd_details["description"],
        )
        for param in cmd_details.get("parameters", []):
            additional_params.append(param)
    additional_params = "\n".join(additional_params)
    doc_string = __doc__ % (additional_commands, additional_params)

    args = docopt(doc_string, options_first=True)

    if args["--version"]:
        print(constants.VERSION)
        sys.exit(0)

    if args["--debug"]:
        config.DEBUG = True
        os.environ["DEBUG"] = "1"

    # set up logging (after DEBUG has been configured)
    setup_logging()

    # invoke subcommand
    argv = [args["<command>"]] + args["<args>"]
    subcommand = config.CLI_COMMANDS.get(args["<command>"])
    if subcommand:
        try:
            subcommand["function"](argv, args)
        except Exception as e:
            if os.environ.get("DEBUG") in ["1", "true"]:
                print(traceback.format_exc())
            print("ERROR: %s" % e)
            sys.exit(1)
    else:
        print('ERROR: Invalid command "%s"' % args["<command>"])
        sys.exit(1)


if __name__ == "__main__":
    main()
