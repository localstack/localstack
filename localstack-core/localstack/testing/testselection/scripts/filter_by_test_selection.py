import sys


def filter_test_files(tests: list[str], selected_tests: list[str]):
    """Filter list of test files by test selection file. Result is written to stdout"""

    # TODO: SENTINEL_NO_TESTS ... not sure how we'd handle it here without failing the circleci selection
    if "SENTINEL_ALL_TESTS" in selected_tests:
        for line in tests:
            print(line)
        return

    for line in tests:
        if any(fc in line for fc in selected_tests):
            print(line)


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python -m localstack.testing.testselection.scripts.filter_by_test_selection <file>",
            file=sys.stderr,
        )
        sys.exit(1)

    testselection_file_path = sys.argv[1]
    with open(testselection_file_path, "r") as file:
        selected_tests = [line.strip() for line in file.readlines() if line.strip()]
        test_files = [line.strip() for line in sys.stdin]
        filter_test_files(test_files, selected_tests)


if __name__ == "__main__":
    main()
