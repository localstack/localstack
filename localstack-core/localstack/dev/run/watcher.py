"""File watcher that monitors source directories and signals container restart on changes."""

import os
import threading
import time
from pathlib import Path

from rich.console import Console
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from localstack.dev.run.paths import HOST_PATH_MAPPINGS, HostPaths
from localstack.utils.container_utils.container_client import ContainerClient
from localstack.utils.threads import TMP_THREADS, FuncThread

DEBOUNCE_WINDOW = 0.5


console = Console()


class ChangeHandler(FileSystemEventHandler):
    """Handles file system events for .py files, debouncing and signalling the container."""

    def __init__(
        self,
        directories: list[Path],
        docker: ContainerClient,
        container_id: str,
    ):
        super().__init__()
        self._directories = directories
        self._docker = docker
        self._container_id = container_id
        self._last_signal_time = 0.0
        self._lock = threading.Lock()

    def _relative_path(self, path: str) -> str:
        for d in self._directories:
            try:
                return os.path.relpath(path, d.parent)
            except ValueError:
                pass
        return path

    def on_any_event(self, event: FileSystemEvent):
        if event.is_directory:
            return
        src = event.src_path
        if not src.endswith(".py") or "__pycache__" in src:
            return

        with self._lock:
            now = time.monotonic()
            if now - self._last_signal_time < DEBOUNCE_WINDOW:
                return
            self._last_signal_time = now

        console.print("Live reload: sending restart signal to container")
        _signal_container_restart(self._docker, self._container_id)


def _signal_container_restart(docker: ContainerClient, container_id: str):
    """Send SIGUSR1 to PID 1 inside the container to trigger supervisor restart."""
    try:
        docker.exec_in_container(container_id, ["kill", "-USR1", "1"])
    except Exception as e:
        console.print(f"Live reload: failed to signal container: {e}")


def start_file_watcher(
    directories: list[Path],
    docker: ContainerClient,
    container_id: str,
) -> threading.Event:
    """Start a watchdog observer that watches directories for .py changes and signals the container.

    Returns a stop_event that the caller can set to shut down the watcher.
    """
    console.print(
        f"Live reload: watching {len(directories)} "
        f"director{'y' if len(directories) == 1 else 'ies'} for .py changes"
    )
    for d in directories:
        console.print(f"  {d}")

    handler = ChangeHandler(directories, docker, container_id)
    observer = Observer()
    for d in directories:
        observer.schedule(handler, str(d), recursive=True)
    observer.daemon = True
    observer.start()

    stop_event = threading.Event()

    def _shutdown_when_signalled():
        stop_event.wait()
        observer.stop()

    shutdown_thread = FuncThread(
        func=_shutdown_when_signalled,
        name="live-reload-shutdown",
    )
    shutdown_thread.start()
    TMP_THREADS.append(shutdown_thread)

    return stop_event


def collect_watch_directories(
    host_paths: HostPaths, pro: bool, chosen_packages: list[str] | None
) -> list[Path]:
    """Collect host-side source directories that are bind-mounted into the container."""
    dirs: list[Path] = []

    source = host_paths.aws_community_package_dir
    if source.exists():
        dirs.append(source)

    if pro:
        source = host_paths.aws_pro_package_dir
        if source.exists():
            dirs.append(source)

    for package_name in chosen_packages or []:
        extractor = HOST_PATH_MAPPINGS[package_name]
        path = extractor(host_paths)
        if path.exists():
            dirs.append(path)

    return dirs
