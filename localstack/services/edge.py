import argparse
import logging
import shlex
import subprocess
import sys
from typing import List, Optional, TypeVar

from localstack import config, constants
from localstack.config import HostAndPort
from localstack.constants import (
    LOCALSTACK_ROOT_FOLDER,
)
from localstack.http import Router
from localstack.http.dispatcher import Handler, handler_dispatcher
from localstack.utils.collections import split_list_by
from localstack.utils.net import get_free_tcp_port
from localstack.utils.run import is_root, run
from localstack.utils.server.proxy_server import start_tcp_proxy
from localstack.utils.threads import FuncThread, start_thread

T = TypeVar("T")

LOG = logging.getLogger(__name__)


ROUTER: Router[Handler] = Router(dispatcher=handler_dispatcher())
"""This special Router is part of the edge proxy. Use the router to inject custom handlers that are handled before
the actual AWS service call is made."""


def do_start_edge(
    listen: HostAndPort | List[HostAndPort], use_ssl: bool, asynchronous: bool = False
):
    from localstack.aws.serving.edge import serve_gateway

    return serve_gateway(listen, use_ssl, asynchronous)


def can_use_sudo():
    try:
        run("sudo -n -v", print_error=False)
        return True
    except Exception:
        return False


def ensure_can_use_sudo():
    if not is_root() and not can_use_sudo():
        if not sys.stdin.isatty():
            raise IOError("cannot get sudo password from non-tty input")
        print("Please enter your sudo password (required to configure local network):")
        run("sudo -v", stdin=True)


def start_component(
    component: str, listen_str: str | None = None, target_address: str | None = None
):
    if component == "edge":
        return start_edge(listen_str=listen_str)
    if component == "proxy":
        if target_address is None:
            raise ValueError("no target address specified")

        return start_proxy(
            listen_str=listen_str,
            target_address=HostAndPort.parse(
                target_address,
                default_host=config.default_ip,
                default_port=constants.DEFAULT_PORT_EDGE,
            ),
        )
    raise Exception("Unexpected component name '%s' received during start up" % component)


def start_proxy(
    listen_str: str, target_address: HostAndPort, asynchronous: bool = False
) -> FuncThread:
    """
    Starts a TCP proxy to perform a low-level forwarding of incoming requests.

    :param listen_str: address to listen on
    :param target_address: target address to proxy requests to
    :param asynchronous: False if the function should join the proxy thread and block until it terminates.
    :return: created thread executing the proxy
    """
    listen_hosts = parse_gateway_listen(
        listen_str,
        default_host=constants.LOCALHOST_IP,
        default_port=constants.DEFAULT_PORT_EDGE,
    )
    listen = listen_hosts[0]
    return do_start_tcp_proxy(listen, target_address, asynchronous)


def do_start_tcp_proxy(
    listen: HostAndPort, target_address: HostAndPort, asynchronous: bool = False
) -> FuncThread:
    src = str(listen)
    dst = str(target_address)

    LOG.debug("Starting Local TCP Proxy: %s -> %s", src, dst)
    proxy = start_thread(
        lambda *args, **kwargs: start_tcp_proxy(src=src, dst=dst, handler=None, **kwargs),
        name="edge-tcp-proxy",
    )
    if not asynchronous:
        proxy.join()
    return proxy


def start_edge(listen_str: str, use_ssl: bool = True, asynchronous: bool = False):
    if listen_str:
        listen = parse_gateway_listen(
            listen_str, default_host=config.default_ip, default_port=constants.DEFAULT_PORT_EDGE
        )
    else:
        listen = config.GATEWAY_LISTEN

    if len(listen) == 0:
        raise ValueError("no listen addresses provided")

    # separate privileged and unprivileged addresses
    unprivileged, privileged = split_list_by(listen, lambda addr: addr.is_unprivileged() or False)

    # if we are root, we can directly bind to privileged ports as well
    if is_root():
        unprivileged = unprivileged + privileged
        privileged = []

    # check that we are actually started the gateway server
    if not unprivileged:
        unprivileged = parse_gateway_listen(
            f":{get_free_tcp_port()}",
            default_host=config.default_ip,
            default_port=constants.DEFAULT_PORT_EDGE,
        )

    # bind the gateway server to unprivileged addresses
    edge_thread = do_start_edge(unprivileged, use_ssl=use_ssl, asynchronous=True)

    # start TCP proxies for the remaining addresses
    proxy_destination = unprivileged[0]
    for address in privileged:
        # escalate to root
        args = [
            "proxy",
            "--gateway-listen",
            str(address),
            "--target-address",
            str(proxy_destination),
        ]
        run_module_as_sudo(
            module="localstack.services.edge",
            arguments=args,
            asynchronous=True,
        )

    if edge_thread is not None:
        edge_thread.join()


def run_module_as_sudo(
    module: str, arguments: Optional[List[str]] = None, asynchronous=False, env_vars=None
):
    # prepare environment
    env_vars = env_vars or {}
    env_vars["PYTHONPATH"] = f".:{LOCALSTACK_ROOT_FOLDER}"

    # start the process as sudo
    python_cmd = sys.executable
    cmd = ["sudo", "-n", "--preserve-env", python_cmd, "-m", module]
    arguments = arguments or []
    shell_cmd = shlex.join(cmd + arguments)

    # make sure we can run sudo commands
    try:
        ensure_can_use_sudo()
    except Exception as e:
        LOG.error("cannot run command as root (%s): %s ", str(e), shell_cmd)
        return

    def run_command(*_):
        run(shell_cmd, outfile=subprocess.PIPE, print_error=False, env_vars=env_vars)

    LOG.debug("Running command as sudo: %s", shell_cmd)
    result = (
        start_thread(run_command, quiet=True, name="sudo-edge") if asynchronous else run_command()
    )
    return result


def parse_gateway_listen(listen: str, default_host: str, default_port: int) -> List[HostAndPort]:
    addresses = []
    for address in listen.split(","):
        addresses.append(HostAndPort.parse(address, default_host, default_port))
    return addresses


if __name__ == "__main__":
    logging.basicConfig()
    parser = argparse.ArgumentParser()
    parser.add_argument("component")
    parser.add_argument("-l", "--gateway-listen", required=False, type=str)
    parser.add_argument("-t", "--target-address", required=False, type=str)
    args = parser.parse_args()

    start_component(args.component, args.gateway_listen, args.target_address)
