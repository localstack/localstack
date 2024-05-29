"""
USAGE: $ GITHUB_API_TOKEN=<your-token> python -m localstack.testing.testselection.scripts.generate_test_selection_from_pr <git-root-dir> <output-file-path> [ --pr <pull-request-url> ]
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
from localstack.testing.testselection.opt_in import complies_with_opt_in
from localstack.testing.testselection.testselection import get_affected_tests_from_changes


def generate_from_pr(
    opt_in_rules: Iterable[str] | None = None,
    matching_rules: list[MatchingRule] | None = None,
    repo_name: str = "localstack",
):
    parser = argparse.ArgumentParser(description="Generate test selection from a pull request")
    parser.add_argument("git_root_dir", type=str, help="Path to the git repository root")
    parser.add_argument("output_file_path", type=str, help="Path to the output file")
    parser.add_argument("--pr", type=str, help="Pull request URL")
    args = parser.parse_args()

    output_file_path = args.output_file_path
    repo_root_path = args.git_root_dir
    github_token = os.environ.get("GITHUB_API_TOKEN")
    # Handle the mismatch between python module name and github repo name
    github_repo_name = repo_name.replace("_", "-")

    if args.pr is None:
        current_branch = get_branch_name(repo_root_path)
        print(
            f"No pull request URL provided, evaluating based on current branch ({current_branch})"
        )
        base_commit_sha, head_commit_sha = get_pr_details_from_branch(
            github_repo_name, current_branch, github_token
        )
    else:
        base_commit_sha, head_commit_sha = get_pr_details_from_url(
            github_repo_name, args.pr, github_token
        )

    print(f"Base Commit SHA: {base_commit_sha}")
    print(f"Head Commit SHA: {head_commit_sha}")

    merge_base_commit = find_merge_base(repo_root_path, base_commit_sha, head_commit_sha)
    changed_files = get_changed_files_from_git_diff(
        repo_root_path, merge_base_commit, head_commit_sha
    )
    # opt-in guard, can be removed after initial testing phase
    print("Checking for confirming to opt-in guards")
    if not complies_with_opt_in(changed_files, opt_in_rules=opt_in_rules):
        print(
            f"Change outside of opt-in guards. Extend the list at {repo_name}/testing/testselection/opt_in.py"
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
    generate_from_pr()
