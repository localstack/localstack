import json
import sys
from pathlib import Path


def analyze_perf(file_paths: [str]) -> dict[str, [float]]:
    perfdelta = dict()

    for file_path in file_paths:
        f = open(file_path)
        data = json.load(f)
        for key, value in data.items():
            if key not in perfdelta:
                perfdelta[key] = [value]
            else:
                delta = value - perfdelta[key][0]
                perfdelta[key].append(value)
                perfdelta[key].append(delta)

    return perfdelta


if __name__ == "__main__":
    # Check if at least one command line argument is provided
    if len(sys.argv) < 2:
        print("Usage: python parse.py outfile1.json outfile2.json")
        sys.exit(1)

    # Get the list of file paths from command line arguments
    file_paths = sys.argv[1:]
    perfdelta = analyze_perf(file_paths)

    # Save the output into the same directory as the first input file with a new .json suffix
    first_input = Path(file_paths[0])
    output_file = first_input.parent / f"{first_input.stem}_analyzed.json"
    with open(output_file, "w") as outfile:
        json.dump(perfdelta, outfile)
