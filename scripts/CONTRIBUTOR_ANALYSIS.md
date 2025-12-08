# Contributor Analysis Script

## Overview

The `analyze_contributors.py` script analyzes the git history of the LocalStack repository to identify and count contributors and contributions from outside the LocalStack organization.

## Purpose

This script helps answer questions like:
- How many contributors have contributed to LocalStack?
- How many of these contributors are external (not part of the LocalStack organization)?
- What percentage of commits come from external contributors?
- Who are the top external contributors?

## Usage

### Basic Analysis (with GitHub API)

For the most accurate results, provide a GitHub token to fetch the current organization members:

```bash
export GH_TOKEN="your_github_token"
python scripts/analyze_contributors.py
```

This will use the GitHub API to fetch the list of LocalStack organization members from https://github.com/orgs/localstack/people and accurately identify internal contributors even if they use personal email addresses.

### Basic Analysis (without GitHub API)

Run the script from the repository root to get a summary using the static list derived from CODEOWNERS:

```bash
python scripts/analyze_contributors.py --no-github-api
```

**Output:**
```
======================================================================
LocalStack Repository Contributor Analysis
======================================================================
⚠ Using static list for organization member detection
  (Set GH_TOKEN or GITHUB_TOKEN to use GitHub API)

📊 OVERALL STATISTICS
----------------------------------------------------------------------
Total Contributors:           689
Total Commits:               7603

🏢 LOCALSTACK ORGANIZATION
----------------------------------------------------------------------
Internal Contributors:         28
Internal Commits:            2854
Percentage of Commits:      37.5%

🌍 EXTERNAL CONTRIBUTORS (Outside LocalStack Organization)
----------------------------------------------------------------------
External Contributors:        639
External Commits:            4749
Percentage of Commits:      62.5%
======================================================================
```

### Detailed Analysis

To see a detailed list of external contributors with their commit counts:

```bash
python scripts/analyze_contributors.py --verbose
```

This will include the top 50 external contributors sorted by number of commits.

### Analyze a Different Repository

You can analyze any git repository by specifying the path:

```bash
python scripts/analyze_contributors.py --repo /path/to/repository --verbose
```

## How It Works

### LocalStack Organization Identification

The script identifies LocalStack organization members by checking for:

1. **Email domains:**
   - `@localstack.cloud` - Current LocalStack organization domain
   - `@atlassian.com` - Historical domain when the project was at Atlassian

2. **Bot accounts:**
   - `localstack-bot@users.noreply.github.com`
   - `88328844+localstack-bot@users.noreply.github.com`

3. **GitHub organization usernames** (in noreply addresses):
   - `taras-kobernyk-localstack`

Any contributor not matching these patterns is considered an external contributor.

### Data Collection

The script uses `git log --all --format=%ae|%an` to extract:
- Author email addresses
- Author names
- From all branches and commits in the repository

### Statistics Calculated

- **Total Contributors:** Unique email addresses across all commits
- **Total Commits:** All commits in the repository
- **Internal Contributors:** Contributors identified as part of LocalStack organization
- **Internal Commits:** Commits by internal contributors
- **External Contributors:** Contributors from outside the organization
- **External Commits:** Commits by external contributors

## Accuracy and GitHub API

**Important:** The accuracy of the results depends on whether the GitHub API is used:

### Without GitHub API (--no-github-api flag)
- Uses a static list derived from the CODEOWNERS file
- Can only identify contributors using:
  - `@localstack.cloud` or `@atlassian.com` email domains
  - GitHub noreply emails matching known organization members
- May misclassify organization members who use personal email addresses

### With GitHub API (recommended)
- Fetches the current list of organization members from https://github.com/orgs/localstack/people
- Cross-references GitHub usernames extracted from all email formats
- More accurate classification even when members use personal emails
- Requires a GitHub personal access token with `read:org` permissions

## Key Findings

Based on the current analysis (using static list from CODEOWNERS):

- **62.5%** of commits come from external contributors
- **639** external contributors have contributed to LocalStack
- **4,749** commits have been made by the community outside LocalStack
- **28** internal contributors from the LocalStack organization
- **2,854** commits by organization members

This demonstrates the strong community-driven nature of the LocalStack project!

## Requirements

- Python 3.6+
- Git repository with accessible history
- No external Python dependencies required (uses only standard library)

## Command Line Options

```
usage: analyze_contributors.py [-h] [--repo REPO] [-v]

Analyze git contributors and identify external contributions

options:
  -h, --help     show this help message and exit
  --repo REPO    Path to the git repository (default: current directory)
  -v, --verbose  Show detailed contributor information
```

## Notes

- The script analyzes the entire git history accessible from the current repository
- For accurate results, ensure the repository has full history (not a shallow clone)
- GitHub noreply email addresses are handled to extract usernames where possible
- The script is read-only and does not modify the repository in any way
