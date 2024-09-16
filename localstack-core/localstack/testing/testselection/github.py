import requests

GITHUB_V3_JSON = "application/vnd.github.v3+json"

# We assume that test selection scripts are only run on repositories under the localstack organization
REPO_OWNER = "localstack"


def get_pr_details_from_number(repo_name: str, pr_number: str, token: str) -> (str, str):
    """
    Fetch the base commit SHA, and the head commit SHA of a given pull request number from a GitHub repository.
    """
    url = f"https://api.github.com/repos/{REPO_OWNER}/{repo_name}/pulls/{pr_number}"
    headers = {"Accept": GITHUB_V3_JSON}
    if token:
        headers["Authorization"] = f"token {token}"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise ValueError(f"Failed to fetch PR data for PR #{pr_number}: {response.text}")
    pr_data = response.json()
    return pr_data["base"]["sha"], pr_data["head"]["sha"]


def get_pr_details_from_branch(repo_name: str, branch: str, token: str) -> (str, str):
    """
    Fetch the base commit SHA, and the head commit SHA of a given branch from a GitHub repository.
    """
    url = f"https://api.github.com/repos/{REPO_OWNER}/{repo_name}/pulls?head={REPO_OWNER}:{branch}"
    headers = {"Accept": GITHUB_V3_JSON}
    if token:
        headers["Authorization"] = f"token {token}"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise ValueError(f"Failed to fetch PR data for branch {branch}: {response.text}")
    pr_data = response.json()
    if len(pr_data) != 1:
        raise ValueError(f"Expected 1 PR for branch {branch}, but got {len(pr_data)} PRs")
    print(f"Detected PR Number #{pr_data[0]['number']}")
    return pr_data[0]["base"]["sha"], pr_data[0]["head"]["sha"]


def get_pr_details_from_url(repo_name: str, pr_url: str, token: str) -> (str, str):
    """
    Extract base and head sha from a given PR URL
    Example pr_url: https://github.com/localstack/localstack/pull/1
    """
    parts = pr_url.split("/")
    pr_number = parts[-1]
    return get_pr_details_from_number(repo_name, pr_number, token)
