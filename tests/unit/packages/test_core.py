import pytest

from localstack.packages import PackageException
from localstack.packages.core import GitHubReleaseInstaller


class TestGitHubPackageInstaller(GitHubReleaseInstaller):
    def __init__(self):
        super().__init__(
            "test-package", "test-default-version", "non-existing-user/non-existing-repo"
        )

    def _get_github_asset_name(self):
        return "test-asset-name"


def test_github_installer_does_not_fetch_versions_on_presence_check():
    """
    This test makes ensures that the check if a package installed via the GitHubReleaseInstaller does not require
    requests to GitHub.
    """
    installer = TestGitHubPackageInstaller()
    # Assert that the non-existing package is not installed (a request to a non-existing repo would raise an exception)
    assert not installer.is_installed()


def test_github_installer_raises_exception_on_install_with_non_existing_repo():
    installer = TestGitHubPackageInstaller()
    with pytest.raises(PackageException):
        installer.install()
