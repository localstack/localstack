#!/usr/bin/env python3
"""
Script to analyze git contributors and identify contributions from outside the LocalStack organization.

This script analyzes the git history to count:
- Total unique contributors
- External contributors (outside LocalStack organization)
- Total commits
- Commits from external contributors
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple


# Define LocalStack organization email patterns
LOCALSTACK_DOMAINS = [
    "@localstack.cloud",
    "@atlassian.com",  # Historical domain when project was at Atlassian
]

LOCALSTACK_BOTS = [
    "localstack-bot@users.noreply.github.com",
    "88328844+localstack-bot@users.noreply.github.com",
]

# GitHub usernames that are part of LocalStack organization (for noreply addresses)
# This will be augmented with data from GitHub API if available
# List derived from CODEOWNERS file and known organization members
LOCALSTACK_GITHUB_USERS = [
    "localstack-bot",
    "taras-kobernyk-localstack",
    # From CODEOWNERS file
    "HarshCasper",
    "aidehn",
    "alexrashed",
    "baermat",
    "bentsku",
    "cloutierMat",
    "dfangl",
    "dominikschubert",
    "giograno",
    "gregfurman",
    "joe4dev",
    "k-a-il",
    "macnev2013",
    "maxhoheiser",
    "pinzon",
    "sannya-singal",
    "silv-io",
    "simonrw",
    "steffyP",
    "thrau",
    "tiurin",
    "viren-nadkarni",
]


def extract_github_username(email: str) -> Optional[str]:
    """
    Extract GitHub username from a GitHub noreply email address.
    
    Args:
        email: Email address
    
    Returns:
        GitHub username if found, None otherwise
    """
    # Pattern: <numeric_id>+<username>@users.noreply.github.com
    # or: <username>@users.noreply.github.com
    match = re.match(r'(?:\d+\+)?([^@]+)@users\.noreply\.github\.com', email.lower())
    if match:
        return match.group(1)
    return None


def fetch_github_org_members(org: str = "localstack") -> Set[str]:
    """
    Fetch GitHub organization members using gh CLI.
    
    Args:
        org: GitHub organization name
    
    Returns:
        Set of GitHub usernames in the organization
    """
    try:
        # Check if GH_TOKEN or GITHUB_TOKEN is available
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not token:
            print(
                "Warning: No GitHub token found. Set GH_TOKEN or GITHUB_TOKEN environment variable "
                "to fetch organization members from GitHub API.",
                file=sys.stderr,
            )
            return set()
        
        # Use gh CLI to fetch organization members
        env = os.environ.copy()
        env["GH_TOKEN"] = token
        
        result = subprocess.run(
            ["gh", "api", f"/orgs/{org}/members", "--paginate", "--jq", ".[].login"],
            capture_output=True,
            text=True,
            env=env,
        )
        
        if result.returncode == 0:
            members = set(line.strip().lower() for line in result.stdout.strip().split("\n") if line.strip())
            print(f"Fetched {len(members)} members from GitHub organization '{org}'", file=sys.stderr)
            return members
        else:
            print(
                f"Warning: Failed to fetch organization members: {result.stderr}",
                file=sys.stderr,
            )
            return set()
    except Exception as e:
        print(f"Warning: Error fetching organization members: {e}", file=sys.stderr)
        return set()


def is_localstack_contributor(
    email: str, name: str = "", org_members: Optional[Set[str]] = None
) -> bool:
    """
    Determine if a contributor is part of the LocalStack organization.
    
    Args:
        email: Contributor's email address
        name: Contributor's name (optional)
        org_members: Set of GitHub usernames in the LocalStack organization (optional)
    
    Returns:
        True if the contributor is part of LocalStack organization, False otherwise
    """
    email_lower = email.lower()
    
    # Check for LocalStack email domains
    for domain in LOCALSTACK_DOMAINS:
        if domain in email_lower:
            return True
    
    # Check for LocalStack bot accounts
    if email_lower in [bot.lower() for bot in LOCALSTACK_BOTS]:
        return True
    
    # Extract GitHub username from email if it's a noreply address
    github_username = extract_github_username(email)
    
    # Check against known LocalStack GitHub organization users
    if github_username:
        for username in LOCALSTACK_GITHUB_USERS:
            if github_username.lower() == username.lower():
                return True
    
    # If we have org members list from API, check against that too
    if org_members and github_username:
        if github_username.lower() in org_members:
            return True
    
    return False


def get_git_log(repo_path: str = ".") -> List[Tuple[str, str]]:
    """
    Get git log with author email and name for all commits.
    
    Args:
        repo_path: Path to the git repository
    
    Returns:
        List of tuples containing (email, name) for each commit
    """
    try:
        result = subprocess.run(
            ["git", "log", "--all", "--format=%ae|%an"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        
        commits = []
        for line in result.stdout.strip().split("\n"):
            if line:
                parts = line.split("|", 1)
                if len(parts) == 2:
                    commits.append((parts[0], parts[1]))
                else:
                    # Log warning for malformed lines
                    print(f"Warning: Skipping malformed line: {line[:50]}...", file=sys.stderr)
        
        return commits
    except subprocess.CalledProcessError as e:
        print(f"Error running git log: {e}", file=sys.stderr)
        sys.exit(1)


def analyze_contributors(
    repo_path: str = ".", use_github_api: bool = True
) -> Dict[str, Any]:
    """
    Analyze git repository to count contributors and contributions.
    
    Args:
        repo_path: Path to the git repository
        use_github_api: Whether to fetch organization members from GitHub API
    
    Returns:
        Dictionary containing analysis results
    """
    commits = get_git_log(repo_path)
    
    # Fetch GitHub organization members if requested
    org_members = None
    if use_github_api:
        org_members = fetch_github_org_members("localstack")
    
    # Track unique contributors and their commit counts
    all_contributors: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"name": "", "commits": 0, "is_external": False}
    )
    external_contributors: Set[str] = set()
    external_commits = 0
    
    for email, name in commits:
        is_external = not is_localstack_contributor(email, name, org_members)
        
        # Update contributor info
        all_contributors[email]["name"] = name
        all_contributors[email]["commits"] += 1
        all_contributors[email]["is_external"] = is_external
        
        if is_external:
            external_contributors.add(email)
            external_commits += 1
    
    return {
        "total_commits": len(commits),
        "total_contributors": len(all_contributors),
        "external_contributors": len(external_contributors),
        "external_commits": external_commits,
        "internal_contributors": len(all_contributors) - len(external_contributors),
        "internal_commits": len(commits) - external_commits,
        "all_contributors": dict(all_contributors),
        "used_github_api": org_members is not None and len(org_members) > 0,
    }


def print_summary(results: Dict, verbose: bool = False):
    """
    Print a summary of the analysis results.
    
    Args:
        results: Analysis results dictionary
        verbose: If True, print detailed contributor information
    """
    print("=" * 70)
    print("LocalStack Repository Contributor Analysis")
    print("=" * 70)
    if results.get("used_github_api"):
        print("✓ Using GitHub API for organization member detection")
    else:
        print("⚠ Using static list for organization member detection")
        print("  (Set GH_TOKEN or GITHUB_TOKEN to use GitHub API)")
    print()
    
    # Overall statistics
    print("📊 OVERALL STATISTICS")
    print("-" * 70)
    print(f"Total Contributors:        {results['total_contributors']:>6}")
    print(f"Total Commits:             {results['total_commits']:>6}")
    print()
    
    # Internal (LocalStack organization) statistics
    print("🏢 LOCALSTACK ORGANIZATION")
    print("-" * 70)
    print(f"Internal Contributors:     {results['internal_contributors']:>6}")
    print(f"Internal Commits:          {results['internal_commits']:>6}")
    internal_commit_pct = (results['internal_commits'] / results['total_commits'] * 100) if results['total_commits'] > 0 else 0
    print(f"Percentage of Commits:     {internal_commit_pct:>5.1f}%")
    print()
    
    # External (outside organization) statistics
    print("🌍 EXTERNAL CONTRIBUTORS (Outside LocalStack Organization)")
    print("-" * 70)
    print(f"External Contributors:     {results['external_contributors']:>6}")
    print(f"External Commits:          {results['external_commits']:>6}")
    external_commit_pct = (results['external_commits'] / results['total_commits'] * 100) if results['total_commits'] > 0 else 0
    print(f"Percentage of Commits:     {external_commit_pct:>5.1f}%")
    print()
    
    # Verbose output with detailed contributor information
    if verbose:
        print("=" * 70)
        print("DETAILED EXTERNAL CONTRIBUTOR LIST")
        print("=" * 70)
        
        # Sort external contributors by commit count (descending)
        external_list = [
            (email, info["name"], info["commits"])
            for email, info in results["all_contributors"].items()
            if info["is_external"]
        ]
        external_list.sort(key=lambda x: x[2], reverse=True)
        
        print(f"\nTop External Contributors (Total: {len(external_list)}):")
        print("-" * 70)
        print(f"{'Commits':<10} {'Name':<30} {'Email':<30}")
        print("-" * 70)
        
        # Show top 50 external contributors
        for email, name, commits in external_list[:50]:
            name_truncated = name[:28] + ".." if len(name) > 28 else name
            email_truncated = email[:28] + ".." if len(email) > 28 else email
            print(f"{commits:<10} {name_truncated:<30} {email_truncated:<30}")
        
        if len(external_list) > 50:
            print(f"\n... and {len(external_list) - 50} more external contributors")
    
    print()
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze git contributors and identify external contributions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis with GitHub API
  python analyze_contributors.py

  # Detailed analysis with contributor list
  python analyze_contributors.py --verbose

  # Analysis without GitHub API (faster but less accurate)
  python analyze_contributors.py --no-github-api

  # Analyze a different repository
  python analyze_contributors.py --repo /path/to/repo --verbose

Note:
  To use GitHub API to fetch organization members, set GH_TOKEN or GITHUB_TOKEN
  environment variable with a valid GitHub personal access token.
        """,
    )
    
    parser.add_argument(
        "--repo",
        default=".",
        help="Path to the git repository (default: current directory)",
    )
    
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed contributor information",
    )
    
    parser.add_argument(
        "--no-github-api",
        action="store_true",
        help="Skip fetching organization members from GitHub API (faster but less accurate)",
    )
    
    args = parser.parse_args()
    
    # Analyze the repository
    results = analyze_contributors(args.repo, use_github_api=not args.no_github_api)
    
    # Print the summary
    print_summary(results, verbose=args.verbose)


if __name__ == "__main__":
    main()
