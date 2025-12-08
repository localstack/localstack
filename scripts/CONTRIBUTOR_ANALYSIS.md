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

### Basic Analysis

Run the script from the repository root to get a summary of contributor statistics:

```bash
python scripts/analyze_contributors.py
```

**Output:**
```
======================================================================
LocalStack Repository Contributor Analysis
======================================================================

📊 OVERALL STATISTICS
----------------------------------------------------------------------
Total Contributors:           667
Total Commits:               7600

🏢 LOCALSTACK ORGANIZATION
----------------------------------------------------------------------
Internal Contributors:         17
Internal Commits:            1463
Percentage of Commits:      19.2%

🌍 EXTERNAL CONTRIBUTORS (Outside LocalStack Organization)
----------------------------------------------------------------------
External Contributors:        650
External Commits:            6137
Percentage of Commits:      80.8%
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

## Key Findings

Based on the current analysis (as of the last run):

- **80.8%** of commits come from external contributors
- **650** external contributors have contributed to LocalStack
- **6,137** commits have been made by the community outside LocalStack

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
