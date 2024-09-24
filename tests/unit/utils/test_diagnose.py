from unittest.mock import patch

from localstack.utils.diagnose import get_docker_image_details
from localstack.utils.docker_utils import DOCKER_CLIENT


class TestDiagnoseEndpoint:
    @patch.object(
        DOCKER_CLIENT, "inspect_container", return_value={"Config": {"Image": "mocked-image"}}
    )
    @patch.object(
        DOCKER_CLIENT,
        "inspect_image",
        return_value={
            "RepoDigests": [
                "mocked-image@sha256:ee339698cadbee0f7ec7057407973c944e0b834798b1b54829f074aff288388c"
            ],
            "Id": "sha256:ababababababd18ca91ec21fe09b5cb77ec3959f0623d9c8b24006d5c59bd391",
            "RepoTags": ["mocked-image:latest"],
            "Created": "2024-08-25T10:41:47.724301163Z",
        },
    )
    def test_diagnose_non_default_image(self, mocked_image, mocked_inspect):
        image_details = get_docker_image_details()
        assert image_details["id"] == "abababababab"
        assert (
            image_details["sha256"]
            == "ee339698cadbee0f7ec7057407973c944e0b834798b1b54829f074aff288388c"
        )
        assert image_details["tag"] == "latest"
        assert image_details["created"] == "2024-08-25T10:41:47"

        mocked_inspect.assert_called_once()
        mocked_image.assert_called_once_with("mocked-image")
