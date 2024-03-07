import sys


def filter_files(filter_content: list[str]):
    """Filter stdin files by content, matching against target_content."""
    lines = [line.strip() for line in sys.stdin]

    # TODO: SENTINEL_NO_TESTS ... not sure how we'd handle it here without failing the circleci selection
    if "SENTINEL_ALL_TESTS" in filter_content:
        for line in lines:
            print(line)
        return

    for line in lines:
        if any(fc in line for fc in filter_content):
            print(line)


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python -m localstack.testing.testselection.scripts.filter_by_test_selection <file>",
            file=sys.stderr,
        )
        sys.exit(1)

    file_path = sys.argv[1]
    with open(file_path, "r") as file:
        filter_content = [line.strip() for line in file.readlines() if line.strip()]
        filter_files(filter_content)


if __name__ == "__main__":
    main()
