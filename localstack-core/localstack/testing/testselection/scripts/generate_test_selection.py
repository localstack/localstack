"""
USAGE: python -m localstack.testing.testselection.scripts.generate_test_selection <repo_root_path> <output_file_path> \
                                [--base-commit-sha <base-commit-sha> \
                                 --head-commit-sha <head-commit-sha> ]
                                [ --pr-url <pr_url> ]
Optionally set the GITHUB_API_TOKEN environment variable to use the GitHub API.
(when using --pr-url, or no commit SHAs provided)
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Iterable

from localstack.testing.testselection.git import (
    find_merge_base,
    get_branch_name,
    get_changed_files_from_git_diff,
)
from localstack.testing.testselection.github import (
    get_pr_details_from_branch,
    get_pr_details_from_url,
)
from localstack.testing.testselection.matching import MatchingRule
from localstack.testing.testselection.opt_out import opted_out
from localstack.testing.testselection.testselection import get_affected_tests_from_changes


def generate_test_selection(
    opt_out: Iterable[str] | None = None,
    matching_rules: list[MatchingRule] | None = None,
    repo_name: str = "localstack",
):
    parser = argparse.ArgumentParser(
        description="Generate test selection from a range of commits or a PR URL. "
        "Determine the corresponding PR based on the current branch if neither provided."
    )
    parser.add_argument("repo_root_path", type=str, help="Path to the git repository root")
    parser.add_argument("output_file_path", type=str, help="Path to the output file")

    parser.add_argument(
        "--base-commit-sha",
        type=str,
        help="Base commit SHA",
    )
    parser.add_argument(
        "--head-commit-sha",
        type=str,
        help="Head commit SHA",
    )
    parser.add_argument(
        "--pr-url",
        type=str,
        help="URL to a PR",
    )

    args = parser.parse_args()

    repo_root_path = args.repo_root_path
    output_file_path = args.output_file_path
    github_token = os.environ.get("GITHUB_API_TOKEN")
    # Handle the mismatch between python module name and github repo name on dependent modules
    github_repo_name = repo_name.replace("_", "-")

    if args.base_commit_sha is not None and args.head_commit_sha is not None:
        base_commit_sha = args.base_commit_sha
        head_commit_sha = args.head_commit_sha
    elif args.pr_url is not None:
        print(f"PR URL: {args.pr_url}")
        base_commit_sha, head_commit_sha = get_pr_details_from_url(
            repo_name, args.pr_url, github_token
        )
    else:
        print("Neither commit SHAs nor PR URL provided.")
        current_branch = get_branch_name(repo_root_path)
        print(f"Determining based on current branch. ({current_branch})")
        base_commit_sha, head_commit_sha = get_pr_details_from_branch(
            github_repo_name, current_branch, github_token
        )

    print(f"Base Commit SHA: {base_commit_sha}")
    print(f"Head Commit SHA: {head_commit_sha}")

    merge_base_commit = find_merge_base(repo_root_path, base_commit_sha, head_commit_sha)
    changed_files = get_changed_files_from_git_diff(
        repo_root_path, merge_base_commit, head_commit_sha
    )

    print("Checking for confirming to opt-in guards")
    if opted_out(changed_files, opt_out=opt_out):
        print(
            f"Explicitly opted out changed file. Remove from {repo_name}/testing/testselection/opt_out.py if needed"
        )
        test_files = ["SENTINEL_ALL_TESTS"]
    else:
        test_files = get_affected_tests_from_changes(changed_files, matching_rules=matching_rules)

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
        for test_file in test_files:
            fd.write(test_file)
            fd.write("\n")

    print(f"Successfully written test selection to {output_file_path}")


if __name__ == "__main__":
    generate_test_selection()
