import os
from pathlib import Path
from queue import Queue
from threading import Event, RLock
from typing import List, Optional

import pytest

from localstack.packages import InstallTarget, Package, PackageInstaller
from localstack.utils.files import rm_rf
from localstack.utils.threads import FuncThread


class TestPackage(Package):
    def __init__(self):
        super().__init__("Test Package", "test-version")

    def get_versions(self) -> List[str]:
        return ["test-version"]

    def _get_installer(self, version: str) -> PackageInstaller:
        return TestPackageInstaller(version=version)


class TestPackageInstaller(PackageInstaller):
    def __init__(self, version: str, install_lock: Optional[RLock] = None):
        super().__init__("test-installer", version, install_lock)

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "test-installer-marker")

    def _install(self, target: InstallTarget) -> None:
        path = Path(os.path.join(self._get_install_dir(target), "test-installer-marker"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()


@pytest.fixture(scope="module")
def test_package():
    package = TestPackage()
    if package.get_installed_dir():
        rm_rf(package.get_installed_dir())

    yield package

    if package.get_installed_dir():
        rm_rf(package.get_installed_dir())


def test_package_get_installer_caches_installers(test_package):
    assert test_package.get_installer() is test_package.get_installer(test_package.default_version)


def test_package_get_installed_dir_returns_none(test_package):
    assert test_package.get_installed_dir() is None


def test_package_get_installed_dir_returns_install_dir(test_package):
    test_package.install()
    assert test_package.get_installed_dir() is not None


class LockingTestPackageInstaller(PackageInstaller):
    """
    Package installer class used for testing the locking behavior.
    """

    def __init__(self, queue: Queue = Queue(), install_lock: Optional[RLock] = None):
        super().__init__("lock-test-installer", "test", install_lock)
        self.queue = queue
        self.about_to_wait = Event()

    def _get_install_marker_path(self, target: InstallTarget) -> str:
        return "/non-existing-path"

    def set_event(self, event: Event, name: str):
        self.event = event
        self.name = name

    def _install(self, target: InstallTarget) -> None:
        # Store the object references before waiting for the event (it might be changed in the meantime)
        event_at_the_time = self.event
        name_at_the_time = self.name
        self.about_to_wait.set()
        event_at_the_time.wait()
        self.queue.put(name_at_the_time)


def test_package_installer_default_lock():
    # Create a single instance of the installer (by default single instance installer's install methods are mutex)
    installer = LockingTestPackageInstaller()

    # Set that the installer should wait for event 1 and start
    event_installer_1 = Event()
    installer.set_event(event_installer_1, "installer1")
    # Run the installer in a new thread
    FuncThread(func=installer.install).start()
    # Wait for installer 1 to wait for the event
    installer.about_to_wait.wait()
    # Create a new event and set it as the new event to wait for
    event_installer_2 = Event()
    installer.set_event(event_installer_2, "installer2")
    # Again, run the installer in a new thread
    FuncThread(func=installer.install).start()
    # Release the second installer (by setting the event)
    event_installer_2.set()
    # Afterwards release the first installer
    event_installer_1.set()
    # Since the first installer should have the lock when being first run, ensure it finishes first
    assert installer.queue.get() == "installer1"


def test_package_installer_custom_lock():
    shared_lock = RLock()
    shared_queue = Queue()

    # Create the two installers with the same shared lock
    installer_1 = LockingTestPackageInstaller(queue=shared_queue, install_lock=shared_lock)
    installer_2 = LockingTestPackageInstaller(queue=shared_queue, install_lock=shared_lock)

    # Set that the installer 1 should wait for event 1 and start
    event_installer_1 = Event()
    installer_1.set_event(event_installer_1, "installer1")
    FuncThread(func=installer_1.install).start()

    # Create a new event and set it as the new event for installer 2 to wait for
    event_installer_2 = Event()
    installer_2.set_event(event_installer_2, "installer2")
    # Again, run the installer in a new thread
    FuncThread(func=installer_2.install).start()

    # Wait for installer 1 to wait for the event (it acquired the shared lock)
    installer_1.about_to_wait.wait()

    # Release the second installer (by setting the event)
    event_installer_2.set()
    # Afterwards release the first installer
    event_installer_1.set()

    first_finished_installer = shared_queue.get(block=True)
    # Since the first installer should have the lock when being first run, ensure it finishes first
    assert first_finished_installer == "installer1"
