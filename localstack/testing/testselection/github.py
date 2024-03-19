import requests


def get_pr_details(repo_name: str, pr_number: str, token: str) -> (str, str):
    """
    Fetch the base commit SHA, and the head commit SHA of a given pull request number from a GitHub repository.
    """
    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
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
