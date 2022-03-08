import platform
from functools import lru_cache


def is_mac_os() -> bool:
    return "darwin" == platform.system().lower()


def is_linux() -> bool:
    return "linux" == platform.system().lower()


def is_windows() -> bool:
    return "windows" == platform.system().lower()


@lru_cache()
def is_debian() -> bool:
    from localstack.utils.files import load_file

    return "Debian" in load_file("/etc/issue", "")


@lru_cache()
def is_redhat() -> bool:
    from localstack.utils.files import load_file

    return "rhel" in load_file("/etc/os-release", "")


def get_arch() -> str:
    """
    Returns the current machine architecture
    :return: "amd64" when x86_64, "arm64" if aarch64, platform.machine() otherwise
    """
    arch = platform.machine()
    if arch == "x86_64":
        return "amd64"
    if arch == "aarch64":
        return "arm64"
    return arch


def get_os() -> str:
    if is_mac_os():
        return "osx"
    if is_linux():
        return "linux"
    if is_windows():
        return "windows"
    raise ValueError("Unable to determine local operating system")


def in_docker() -> bool:
    from localstack import config

    return config.in_docker()
