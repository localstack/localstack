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


# def find_test_files_without_owner() -> list[str]:
#     ownerless_files = []
#     owners = load_codeowners()
#     for globbed in glob.glob("/home/dominik/work/localstack/localstack/tests/**/test_*.py", recursive=True):
#         rel_path = Path(globbed).relative_to("/home/dominik/work/localstack/localstack")
#         test_owners = owners.of(str(rel_path))
#         if not test_owners:
#             ownerless_files.append(rel_path)
#     return ownerless_files


def create_test_entry(entry, *, code_owners: CodeOwners, commit_sha: str, github_repo: str):
    rel_path = "".join(entry["file_path"].partition("tests/")[1:])
    return TestEntry(
        pytest_node_id=entry["node_id"],
        file_path=rel_path,
        owners=[o[1] for o in code_owners.of(rel_path)],
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
            k: v for k, v in input_data["aggregated_report"].items() if k not in {"parametrize"}
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
