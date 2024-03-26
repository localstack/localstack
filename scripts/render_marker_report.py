"""
This script generates a markdown file with a summary of the current pytest marker usage,
as well as a list of certain markers, their corresponding tests and the CODEOWNERs of these tests.

It takes a pytest marker report generated by localstack.testing.pytest.marker_report
and extends it with data from the CODEOWNERS file.
The resulting data is processed by using a jinja2 template for the resulting GH issue template.


Example on how to run this script manually:

$ MARKER_REPORT_PATH='./target/marker-report.json' \
    CODEOWNERS_PATH=./CODEOWNERS \
    TEMPLATE_PATH=./.github/bot_templates/MARKER_REPORT_ISSUE.md.j2 \
    OUTPUT_PATH=./target/MARKER_REPORT_ISSUE.md \
    GITHUB_REPO=localstack/localstack \
    COMMIT_SHA=e62e04509d0f950af3027c0f6df4e18c7385c630 \
    python scripts/render_marker_report.py
"""

import dataclasses
import datetime
import json
import os

import jinja2
from codeowners import CodeOwners


@dataclasses.dataclass
class EnrichedReportMeta:
    timestamp: str
    repo_url: str
    commit_sha: str


@dataclasses.dataclass
class TestEntry:
    file_path: str
    pytest_node_id: str
    owners: list[str]
    file_url: str


@dataclasses.dataclass
class EnrichedReport:
    """an object of this class is passed for template rendering"""

    meta: EnrichedReportMeta
    aggregated: dict[str, int]
    owners_aws_unknown: list[TestEntry]
    owners_aws_needs_fixing: list[TestEntry]


def load_file(filepath: str) -> str:
    with open(filepath, "r") as fd:
        return fd.read()


def load_codeowners(codeowners_path):
    return CodeOwners(load_file(codeowners_path))


def render_template(*, template: str, enriched_report: EnrichedReport) -> str:
    return jinja2.Template(source=template).render(data=enriched_report)


def create_test_entry(entry, *, code_owners: CodeOwners, commit_sha: str, github_repo: str):
    rel_path = "".join(entry["file_path"].partition("tests/")[1:])
    return TestEntry(
        pytest_node_id=entry["node_id"],
        file_path=rel_path,
        owners=[o[1] for o in code_owners.of(rel_path)] or ["?"],
        file_url=f"https://github.com/{github_repo}/blob/{commit_sha}/{rel_path}",
    )


def enrich_with_codeowners(
    *, input_data: dict, github_repo: str, commit_sha: str, code_owners: CodeOwners
) -> EnrichedReport:
    return EnrichedReport(
        meta=EnrichedReportMeta(
            timestamp=datetime.datetime.utcnow().isoformat(),
            repo_url=f"https://github.com/{github_repo}",
            commit_sha=commit_sha,
        ),
        aggregated={
            k: v for k, v in input_data["aggregated_report"].items() if k.startswith("aws_")
        },
        owners_aws_unknown=sorted(
            [
                create_test_entry(
                    e, code_owners=code_owners, github_repo=github_repo, commit_sha=commit_sha
                )
                for e in input_data["entries"]
                if "aws_unknown" in e["markers"]
            ],
            key=lambda x: x.file_path,
        ),
        owners_aws_needs_fixing=sorted(
            [
                create_test_entry(
                    e, code_owners=code_owners, github_repo=github_repo, commit_sha=commit_sha
                )
                for e in input_data["entries"]
                if "aws_needs_fixing" in e["markers"]
            ],
            key=lambda x: x.file_path,
        ),
    )


def main():
    marker_report_path = os.environ["MARKER_REPORT_PATH"]
    codeowners_path = os.environ["CODEOWNERS_PATH"]
    template_path = os.environ["TEMPLATE_PATH"]
    output_path = os.environ["OUTPUT_PATH"]
    github_repo = os.environ["GITHUB_REPO"]
    commit_sha = os.environ["COMMIT_SHA"]

    code_owners = CodeOwners(load_file(codeowners_path))
    marker_report = json.loads(load_file(marker_report_path))
    enriched_report = enrich_with_codeowners(
        input_data=marker_report,
        github_repo=github_repo,
        commit_sha=commit_sha,
        code_owners=code_owners,
    )
    rendered_markdown = render_template(
        template=load_file(template_path), enriched_report=enriched_report
    )
    with open(output_path, "wt") as outfile:
        outfile.write(rendered_markdown)


if __name__ == "__main__":
    main()
