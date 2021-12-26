#!/usr/bin/env python
import re
from collections import defaultdict

from plugin.setuptools import load_entry_points
from setuptools import find_packages, setup


def parse_requirements(lines):
    requirements = defaultdict(list)
    extra = "install"

    for line in lines:
        line = line.strip()
        if line.startswith("# extra="):
            # all subsequent lines are associated with this extra, until a new extra appears
            extra = line.split("=")[1]
            continue

        if line and line[0] == "#" and "#egg=" in line:
            line = re.search(r"#\s*(.*)", line).group(1)

        if line and line[0] != "#":
            lib_stripped = line.split(" #")[0].strip()
            requirements[extra].append(lib_stripped)

    return requirements


# define package data
package_data = {
    "": ["Makefile", "*.md"],
    "localstack": [
        "package.json",
        "requirements*.txt",
        "utils/kinesis/java/cloud/localstack/*.*",
    ],
}

# determine requirements
with open("requirements.txt") as f:
    req = parse_requirements(f.readlines())

install_requires = req["install"]

extras_require = {
    "cli": req["install"],
    "runtime": req["runtime"],
    "test": req["test"],
    "dev": req["dev"],
}
extras_require["full"] = extras_require["cli"] + extras_require["runtime"]  # deprecated

if __name__ == "__main__":
    setup(
        scripts=["bin/localstack", "bin/localstack.bat"],
        packages=find_packages(exclude=("tests", "tests.*")),
        package_data=package_data,
        install_requires=install_requires,
        extras_require=extras_require,
        entry_points=load_entry_points(exclude=("tests", "tests.*")),
        test_suite="tests",
    )
