import os
import sys
from pathlib import Path

import requests

from localstack.testing import testselection


def get_pr_details(repo_name: str, pr_number: str, token: str) -> (str, str):
    """
    Fetch the base commit SHA, and the head commit SHA of a given pull request number from a GitHub repository.
    """
    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    pr_data = requests.get(url, headers=headers).json()
    return pr_data["base"]["sha"], pr_data["head"]["sha"]


def get_pr_details_from_url(pr_url: str, token: str) -> (str, str):
    """
    Extract base and head sha from a given PR URL
    Example pr_url: https://github.com/localstack/localstack/pull/1
    """
    parts = pr_url.split("/")
    repo_name = f"{parts[-4]}/{parts[-3]}"
    pr_number = parts[-1]
    return get_pr_details(repo_name, pr_number, token)


if __name__ == "__main__":
    output_file_path = sys.argv[-1]
    pull_request_url = sys.argv[-2]
    repo_root_path = sys.argv[-3]

    github_token = os.environ["GITHUB_API_TOKEN"]

    base_commit_sha, head_commit_sha = get_pr_details_from_url(pull_request_url, github_token)
    print(f"Pull request: {pull_request_url}")
    print(f"Base Commit SHA: {base_commit_sha}")
    print(f"Head Commit SHA: {head_commit_sha}")

    merge_base_commit = testselection.find_merge_base(
        repo_root_path, base_commit_sha, head_commit_sha
    )
    changed_files = testselection.get_changed_files_from_git_diff(
        repo_root_path, merge_base_commit, head_commit_sha
    )
    test_files = testselection.get_affected_tests_from_changes(changed_files)

    print(f"Number of changed files detected: {len(changed_files)}")
    for cf in sorted(changed_files):
        print(f"\t{cf}")
    print(f"Number of affected test determined: {len(test_files)}")
    for tf in sorted(test_files):
        print(f"\t{tf}")

    if not test_files:
        print("No tests selected, returning")
        sys.exit(0)

    print(f"Writing test selection to {output_file_path}")
    output_file = Path(output_file_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as fd:
        fd.writelines(sorted(test_files))
        fd.write("\n")

    print(f"Successfully written test selection to {output_file_path}")
