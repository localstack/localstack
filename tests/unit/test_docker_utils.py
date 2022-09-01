from unittest import mock

from localstack.utils.container_utils.container_client import VolumeInfo
from localstack.utils.docker_utils import get_host_path_for_path_in_docker


class TestDockerUtils:
    def test_host_path_for_path_in_docker_windows(self):
        with mock.patch(
            "localstack.utils.docker_utils.get_default_volume_dir_mount"
        ) as get_volume, mock.patch("localstack.config.is_in_docker", True):
            get_volume.return_value = VolumeInfo(
                type="bind",
                source=r"C:\Users\localstack\volume\mount",
                destination="/var/lib/localstack",
                mode="rw",
                rw=True,
                propagation="rprivate",
            )
            result = get_host_path_for_path_in_docker("/var/lib/localstack/some/test/file")
            get_volume.assert_called_once()
            # this path style is kinda weird, but windows will accept it - no need for manual conversion of / to \
            assert result == r"C:\Users\localstack\volume\mount/some/test/file"

    def test_host_path_for_path_in_docker_linux(self):
        with mock.patch(
            "localstack.utils.docker_utils.get_default_volume_dir_mount"
        ) as get_volume, mock.patch("localstack.config.is_in_docker", True):
            get_volume.return_value = VolumeInfo(
                type="bind",
                source="/home/some-user/.cache/localstack/volume",
                destination="/var/lib/localstack",
                mode="rw",
                rw=True,
                propagation="rprivate",
            )
            result = get_host_path_for_path_in_docker("/var/lib/localstack/some/test/file")
            get_volume.assert_called_once()
            assert result == "/home/some-user/.cache/localstack/volume/some/test/file"

    def test_host_path_for_path_in_docker_linux_volume_dir(self):
        with mock.patch(
            "localstack.utils.docker_utils.get_default_volume_dir_mount"
        ) as get_volume, mock.patch("localstack.config.is_in_docker", True):
            get_volume.return_value = VolumeInfo(
                type="bind",
                source="/home/some-user/.cache/localstack/volume",
                destination="/var/lib/localstack",
                mode="rw",
                rw=True,
                propagation="rprivate",
            )
            result = get_host_path_for_path_in_docker("/var/lib/localstack")
            get_volume.assert_called_once()
            assert result == "/home/some-user/.cache/localstack/volume"

    def test_host_path_for_path_in_docker_linux_wrong_path(self):
        with mock.patch(
            "localstack.utils.docker_utils.get_default_volume_dir_mount"
        ) as get_volume, mock.patch("localstack.config.is_in_docker", True):
            get_volume.return_value = VolumeInfo(
                type="bind",
                source="/home/some-user/.cache/localstack/volume",
                destination="/var/lib/localstack",
                mode="rw",
                rw=True,
                propagation="rprivate",
            )
            result = get_host_path_for_path_in_docker("/var/lib/localstacktest")
            get_volume.assert_called_once()
            assert result == "/var/lib/localstacktest"
            result = get_host_path_for_path_in_docker("/etc/some/path")
            assert result == "/etc/some/path"
