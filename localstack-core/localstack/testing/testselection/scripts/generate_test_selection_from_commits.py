"""
USAGE: $ python -m localstack.testing.testselection.scripts.generate_test_selection_from_commits <repo_root_path> <base-commit-sha> <head-commit-sha> <output_file_path>
"""

import argparse
import sys
from pathlib import Path
from typing import Iterable

from localstack.testing.testselection.git import find_merge_base, get_changed_files_from_git_diff
from localstack.testing.testselection.matching import MatchingRule
from localstack.testing.testselection.opt_in import complies_with_opt_in
from localstack.testing.testselection.testselection import get_affected_tests_from_changes


def generate_from_commits(
    opt_in_rules: Iterable[str] | None = None,
    matching_rules: list[MatchingRule] | None = None,
    repo_name: str = "localstack",
):
    parser = argparse.ArgumentParser(description="Generate test selection from a range of commits")
    parser.add_argument("repo_root_path", type=str, help="Path to the git repository root")
    parser.add_argument("base_commit_sha", type=str, help="Base commit SHA")
    parser.add_argument("head_commit_sha", type=str, help="Head commit SHA")
    parser.add_argument("output_file_path", type=str, help="Path to the output file")

    args = parser.parse_args()

    output_file_path = args.output_file_path
    head_commit_sha = args.head_commit_sha
    base_commit_sha = args.base_commit_sha
    repo_root_path = args.repo_root_path

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
    generate_from_commits()
