import json
import sys
from json import JSONDecodeError
from pathlib import Path

PREFIX = "test-perf-timelog:"


def parse_logs(paths: [str]) -> dict[str, float]:
    testperf = dict()

    for path in paths:
        with open(path, "r") as file:
            for line in file:
                if line.startswith(PREFIX):
                    stripped_line = f"{line.partition(PREFIX)[2].rpartition('}')[0]}}}"
                    try:
                        line_json = json.loads(stripped_line)
                    except JSONDecodeError as e:
                        print(f"Skipping line {line} due to JSON decoding error {e}")
                    testperf[line_json["nodeid"]] = line_json["timediff"]
    return testperf


if __name__ == "__main__":
    # Check if at least one command line argument is provided
    if len(sys.argv) < 2:
        print("Usage: python analyze.py logfile1 logfile2 ...")
        sys.exit(1)

    # Get the list of file paths from command line arguments
    file_paths = sys.argv[1:]
    testperf = parse_logs(file_paths)

    # Save the output into the same directory as the first input file with a new .json suffix
    first_input = Path(file_paths[0])
    output_file = first_input.parent / f"{first_input.stem}_parsed.json"
    with open(output_file, "w") as outfile:
        json.dump(testperf, outfile)
