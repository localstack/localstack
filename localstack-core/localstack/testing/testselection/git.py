import subprocess


def get_changed_files_from_git_diff(repo: str, base_ref: str, head_ref: str) -> [str]:
    """
    Find list of files that are affected by changes made on head_ref in comparison to the base_ref.
    The base_ref is usually a merge-base of the actual base ref (just like how GitHub shows you the changes in comparison to latest master)
    """
    cmd = ["git", "-C", repo, "diff", "--name-only", base_ref, head_ref]
    output = subprocess.check_output(cmd, encoding="UTF-8")
    return [line.strip() for line in output.splitlines() if line.strip()]


def find_merge_base(repo: str, base_branch: str, head_branch: str) -> str:
    cmd = ["git", "-C", repo, "merge-base", base_branch, head_branch]
    output = subprocess.check_output(cmd, encoding="UTF-8")
    return output.strip()


def get_branch_name(repo: str) -> str:
    cmd = ["git", "-C", repo, "rev-parse", "--abbrev-ref", "HEAD"]
    output = subprocess.check_output(cmd, encoding="UTF-8")
    return output.strip()
